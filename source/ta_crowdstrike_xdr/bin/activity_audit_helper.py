import json
import logging
import time
import sys
import os
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

import import_declare_test
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi
import crowdstrike_constants as const

try:
    from falconpy import APIHarnessV2, EventStreams
    from falconpy._constant import USER_AGENT as FALCONPY_USER_AGENT
except ImportError:
    APIHarnessV2 = None
    EventStreams = None
    FALCONPY_USER_AGENT = None


ADDON_NAME = "ta_crowdstrike_xdr"
CHECKPOINTER_NAME = "ta_crowdstrike_xdr_checkpoints"

# Activity Audit event types to filter for - any event ending in "ActivityAuditEvent"
KNOWN_ACTIVITY_AUDIT_EVENT_TYPES = [
    "APIActivityAuditEvent",
    "UserActivityAuditEvent", 
    "AuthActivityAuditEvent"
]

def is_activity_audit_event(event_type: str) -> bool:
    """
    Check if an event type is an Activity Audit event.
    Returns True for any event type ending in 'ActivityAuditEvent'.
    """
    if not event_type:
        return False
    return event_type.endswith('ActivityAuditEvent')


def get_custom_user_agent():
    """Create a custom user agent that identifies the add-on and includes FalconPy version."""
    if FALCONPY_USER_AGENT:
        return f"{ADDON_NAME}/1.0.0 {FALCONPY_USER_AGENT}"
    else:
        return f"{ADDON_NAME}/1.0.0"


class StatusCodeErrors:
    """Enhanced status code error handling for CrowdStrike API responses"""
    
    @staticmethod
    def handle_status_code_errors(response: Dict[str, Any], api_endpoint: str, log_label: str, logger: logging.Logger) -> None:
        """
        Handle status code errors from CrowdStrike API responses with enhanced logging
        
        Args:
            response: API response dictionary
            api_endpoint: Name of the API endpoint that was called
            log_label: Label for logging context
            logger: Logger instance
        """
        status_code = response.get('status_code')
        logger.info(f"{log_label}: Response code from the {api_endpoint} = {status_code}")
        
        status_code_str = str(status_code)
        
        try:
            if status_code_str.startswith('40'):
                # 4xx Client Errors (Authentication, Authorization, Bad Request, etc.)
                cs_traceid = None
                cs_error_msg = "Unknown client error"
                
                # Try to extract trace ID from body meta
                if 'body' in response and isinstance(response['body'], dict):
                    meta = response['body'].get('meta', {})
                    if isinstance(meta, dict):
                        cs_traceid = meta.get('trace_id')
                    
                    # Extract error message
                    errors = response['body'].get('errors', [])
                    if errors and isinstance(errors, list) and len(errors) > 0:
                        cs_error_msg = errors[0].get('message', cs_error_msg)
                
                # Log the error details
                if cs_traceid:
                    logger.error(f"{log_label}: Error contacting the CrowdStrike API, please provide this TraceID to CrowdStrike support = {cs_traceid}")
                
                logger.error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
                
            elif status_code_str.startswith('50'):
                # 5xx Server Errors
                cs_error_msg = "Unknown server error"
                
                # Extract error message from response body
                if 'body' in response and isinstance(response['body'], dict):
                    errors = response['body'].get('errors', [])
                    if errors and isinstance(errors, list) and len(errors) > 0:
                        cs_error_msg = errors[0].get('message', cs_error_msg)
                
                logger.error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
                
            else:
                # Other status codes (3xx, etc.)
                cs_traceid = None
                cs_error_msg = "Unknown error"
                
                # Try to extract trace ID from headers
                if 'headers' in response and isinstance(response['headers'], dict):
                    cs_traceid = response['headers'].get('X-Cs-Traceid')
                
                # Extract error message from response body
                if 'body' in response and isinstance(response['body'], dict):
                    errors = response['body'].get('errors', [])
                    if errors and isinstance(errors, list) and len(errors) > 0:
                        cs_error_msg = errors[0].get('message', cs_error_msg)
                
                # Log the error details
                if cs_traceid:
                    logger.error(f"{log_label}: Error contacting the CrowdStrike API, please provide this TraceID to CrowdStrike support = {cs_traceid}")
                
                logger.error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
        
        except Exception as parse_error:
            # If we can't parse the error response, log what we can
            logger.error(f"{log_label}: Failed to parse error response: {parse_error}")
        
        # Add full response for debugging if debug logging is enabled
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"{log_label}: Full API response: {response}")
        
        logger.error(f"{log_label}: API call failed, continuing with error handling")


def create_api_context(api_endpoint: str, operation: str, **kwargs) -> Dict[str, Any]:
    """
    Create a standardized context dictionary for API operations
    
    Args:
        api_endpoint: Name of the API endpoint
        operation: Description of the operation being performed
        **kwargs: Additional context data
        
    Returns:
        Dictionary containing API context information
    """
    context = {
        "api_endpoint": api_endpoint,
        "operation": operation,
        "timestamp": datetime.utcnow().isoformat(),
        "addon_name": ADDON_NAME
    }
    
    # Add any additional context provided
    context.update(kwargs)
    
    return context


def log_api_operation_start(logger: logging.Logger, api_endpoint: str, operation: str, **context) -> None:
    """Log the start of an API operation with context"""
    logger.info(f"Starting {operation} via {api_endpoint}")
    if logger.isEnabledFor(logging.DEBUG):
        api_context = create_api_context(api_endpoint, operation, **context)
        logger.debug(f"API operation context: {api_context}")


def log_api_operation_success(logger: logging.Logger, api_endpoint: str, operation: str, result_count: int = None, **context) -> None:
    """Log successful completion of an API operation"""
    if result_count is not None:
        logger.info(f"Successfully completed {operation} via {api_endpoint} - {result_count} items processed")
    else:
        logger.info(f"Successfully completed {operation} via {api_endpoint}")
    
    if logger.isEnabledFor(logging.DEBUG):
        api_context = create_api_context(api_endpoint, operation, result_count=result_count, **context)
        logger.debug(f"API operation success context: {api_context}")


def get_log_level(session_key: str) -> int:
    """Get the log level from the add-on settings.
    
    Args:
        session_key: Splunk session key
        
    Returns:
        The log level as an integer (logging.INFO, logging.DEBUG, etc.)
    """
    try:
        # Get the settings configuration
        settings_cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-ta_crowdstrike_xdr_settings".format(ADDON_NAME)
        )
        
        # Get the logging stanza
        settings_conf = settings_cfm.get_conf("ta_crowdstrike_xdr_settings")
        log_level_str = settings_conf.get("logging", {}).get("loglevel", "INFO")
        
        # Convert string log level to logging constant
        log_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        
        return log_levels.get(log_level_str.upper(), logging.INFO)
        
    except Exception as e:
        # Log the error but don't fail - default to INFO
        try:
            logging.getLogger(__name__).warning(f"Failed to retrieve log level from settings, using INFO: {e}")
        except:
            # If even basic logging fails, just continue silently
            pass
        return logging.INFO


def logger_for_input(session_key: str, input_name: str) -> logging.Logger:
    """Set up a logger instance for the input.
    
    Logs are stored in $SPLUNK_HOME/var/log/splunk/ta_crowdstrike_xdr_*.log
    The log level is determined by the add-on settings (Configuration > Logging)
    """
    # Set up the log directory to ensure logs go to the right place
    try:
        log_dir = os.path.join(os.environ.get('SPLUNK_HOME', ''), 'var', 'log', 'splunk')
        log.Logs.set_context(directory=log_dir, namespace=ADDON_NAME.lower())
    except Exception:
        # If we can't set the context, the solnlib will try to use the default location
        pass
    
    # Create a safe name for the logger
    safe_input_name = input_name.replace(" ", "_").replace(":", "_").replace("/", "_").replace("\\", "_")
    logger_name = f"{safe_input_name}"
    
    # Get the logger and set the log level from settings
    logger = log.Logs().get_logger(logger_name)
    log_level = get_log_level(session_key)
    logger.setLevel(log_level)
    
    return logger


def get_account_credentials(session_key: str, account_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Get account credentials from configuration.
    
    Args:
        session_key: Splunk session key
        account_name: Name of the account
        
    Returns:
        Tuple of (client_id, client_secret)
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_crowdstrike_xdr_account",
        )
        account_conf_file = cfm.get_conf("ta_crowdstrike_xdr_account")
        account_config = account_conf_file.get(account_name)
        
        if not account_config:
            return None, None
            
        # Get credentials - username is Client ID, api_key is Client Secret
        client_id = account_config.get("username")
        client_secret = account_config.get("api_key")
        
        return client_id, client_secret
        
    except Exception as e:
        # Log the specific error for debugging
        logger = logging.getLogger(__name__)
        logger.error(f"Error retrieving credentials for account '{account_name}': {e}")
        logger.debug(f"Full exception details: {e}", exc_info=True)
        return None, None


def get_checkpoint(logger: logging.Logger, session_key: str, checkpoint_name: str) -> Tuple[bool, Optional[int]]:
    """
    Get checkpoint data from KVStore
    
    Args:
        logger: Logger instance
        session_key: Splunk session key
        checkpoint_name: Name of the checkpoint
        
    Returns:
        Tuple of (success, checkpoint_value_in_milliseconds)
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, ADDON_NAME
        )
        checkpoint_data = checkpoint_collection.get(checkpoint_name)
        if checkpoint_data:
            return True, checkpoint_data.get("last_event_time")
        else:
            # Default to 90 days ago in milliseconds if no checkpoint exists
            default_time_ms = int((datetime.utcnow() - timedelta(days=90)).timestamp() * 1000)
            return True, default_time_ms
    except Exception as e:
        logger.error(f"Error retrieving checkpoint: {e}")
        return False, None


def set_checkpoint(logger: logging.Logger, session_key: str, checkpoint_name: str, checkpoint_value: int) -> bool:
    """
    Set checkpoint data in KVStore
    
    Args:
        logger: Logger instance
        session_key: Splunk session key
        checkpoint_name: Name of the checkpoint
        checkpoint_value: Event creation time in milliseconds to store
        
    Returns:
        Success status
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, ADDON_NAME
        )
        checkpoint_collection.update(checkpoint_name, {'last_event_time': checkpoint_value})
        return True
    except Exception as e:
        logger.error(f"Error setting checkpoint: {e}")
        return False


def get_base_url_from_cloud(cloud_env: str) -> str:
    """
    Get the CrowdStrike base URL from cloud environment setting
    
    Args:
        cloud_env: Cloud environment identifier
        
    Returns:
        Base URL for the specified cloud environment
    """
    # Map cloud environment to base URL
    cloud_mapping = {
        "us_commercial": const.us_commercial_base,
        "us_commercial2": const.us_commercial2_base,
        "govcloud": const.govcloud_base,
        "eucloud": const.eucloud_base
    }
    
    return cloud_mapping.get(cloud_env, const.us_commercial_base)


def get_crowdstrike_activity_audit_data(logger: logging.Logger, client_id: str, client_secret: str, 
                                       base_url: str, last_event_time: int, max_retries: int = 3) -> List[Dict[str, Any]]:
    """
    Get CrowdStrike Activity Audit data using APIHarnessV2 (Uber Class) with EventStreams API
    
    Args:
        logger: Logger instance
        client_id: CrowdStrike client ID
        client_secret: CrowdStrike client secret
        base_url: CrowdStrike base URL
        last_event_time: Last checkpoint event creation time in milliseconds
        max_retries: Maximum number of retry attempts for authentication failures
        
    Returns:
        List of activity audit events for Splunk
    """
    if not APIHarnessV2:
        logger.error("FalconPy APIHarnessV2 not available - cannot retrieve Activity Audit events")
        return []
    
    logger.info(f"Retrieving CrowdStrike Activity Audit events from: {base_url} using APIHarnessV2")
    
    # Retry logic for authentication failures
    for attempt in range(max_retries):
        try:
            logger.debug(f"Authentication attempt {attempt + 1} of {max_retries}")
            
            # Initialize the APIHarnessV2 (Uber Class) with Direct Authentication
            falcon = APIHarnessV2(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                debug=logger.level <= logging.DEBUG,
                user_agent=get_custom_user_agent()
            )
            
            logger.info(f"Successfully initialized CrowdStrike API client (attempt {attempt + 1})")
            logger.debug("Using Direct Authentication - token will be obtained automatically on first API call")
            
            # Step 1: Get available event streams
            logger.info("Step 1: Getting available event streams using APIHarnessV2")
            log_api_operation_start(
                logger=logger,
                api_endpoint="list_available_streams",
                operation="Get available event streams",
                base_url=base_url,
                client_id_length=len(client_id) if client_id else 0,
                last_event_time=last_event_time
            )
            
            app_id = "ActivityAuditCollector"
            streams_response = falcon.command(
                action="list_available_streams",
                appId=app_id,
                format="json"
            )
            
            if streams_response.get("status_code") not in [200, 201]:
                # Check for authentication errors that might be retryable
                status_code = streams_response.get("status_code")
                if status_code in [401, 403] and attempt < max_retries - 1:
                    logger.warning(f"Authentication failed (status {status_code}) on attempt {attempt + 1}, retrying...")
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                
                # Use enhanced error handling
                log_label = "Event Streams Discovery"
                StatusCodeErrors.handle_status_code_errors(
                    response=streams_response,
                    api_endpoint="list_available_streams",
                    log_label=log_label,
                    logger=logger
                )
                return []
            
            # Extract stream URLs from response
            streams = extract_data_feed_urls(streams_response)
            logger.info(f"Step 1 completed: Found {len(streams)} event stream(s)")
            log_api_operation_success(
                logger=logger,
                api_endpoint="list_available_streams",
                operation="Get available event streams",
                result_count=len(streams)
            )
            
            if not streams:
                logger.info("No event streams found")
                return []
            
            # Step 2: Consume events from streams with timestamp filtering
            logger.info("Step 2: Consuming Activity Audit events from streams with timestamp filtering")
            logger.info("Filtering for events ending in 'ActivityAuditEvent' (e.g., APIActivityAuditEvent, UserActivityAuditEvent, AuthActivityAuditEvent)")
            log_api_operation_start(
                logger=logger,
                api_endpoint="consume_event_streams",
                operation="Consume Activity Audit events with timestamp filter",
                total_streams=len(streams),
                last_event_time=last_event_time
            )
            
            all_events = []
            latest_event_time = last_event_time
            
            # Process each stream (typically there's only one)
            for stream_idx, stream_data in enumerate(streams):
                logger.info(f"Processing stream {stream_idx + 1}/{len(streams)}")
                
                # Consume events from this stream with timestamp filtering
                events, new_event_time = consume_activity_audit_events_v2(
                    logger=logger,
                    stream_data=stream_data,
                    last_event_time=last_event_time,
                    stream_idx=stream_idx,
                    timeout=60
                )
                
                all_events.extend(events)
                if new_event_time > latest_event_time:
                    latest_event_time = new_event_time
            
            logger.info(f"Step 2 completed: Retrieved {len(all_events)} Activity Audit events")
            log_api_operation_success(
                logger=logger,
                api_endpoint="consume_event_streams",
                operation="Consume Activity Audit events with timestamp filter",
                result_count=len(all_events),
                latest_event_time=latest_event_time
            )
            
            # Add checkpoint information to events
            for event in all_events:
                if 'ta_data' not in event:
                    event['ta_data'] = {}
                event['ta_data']['latest_event_time'] = latest_event_time
            
            logger.info(f"Activity Audit data collection completed: {len(all_events)} events generated")
            return all_events
            
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Attempt {attempt + 1} failed with error: {e}, retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            else:
                logger.error(f"All {max_retries} attempts failed. Last error: {e}")
                logger.debug(f"Full exception details: {e}", exc_info=True)
                return []
    
    # This should not be reached, but just in case
    logger.error("Unexpected end of retry loop")
    return []


def extract_data_feed_urls(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract dataFeedURLs from EventStreams response."""
    streams = []
    
    if 'body' not in response:
        return streams
    
    body = response['body']
    
    # Standard format with resources array
    if 'resources' in body and isinstance(body['resources'], list):
        for resource in body['resources']:
            # Extract session token correctly, handling different formats
            session_token = None
            if isinstance(resource.get('sessionToken'), dict):
                session_token = resource.get('sessionToken', {}).get('token')
            else:
                session_token = resource.get('sessionToken')
                
            stream_data = {
                'dataFeedURL': resource.get('dataFeedURL'),
                'sessionToken': session_token,
                'refreshActiveSessionURL': resource.get('refreshActiveSessionURL'),
                'partition': resource.get('partition')
            }
            
            # Add domain info
            if stream_data['dataFeedURL']:
                parsed_url = urlparse(stream_data['dataFeedURL'])
                stream_data['domain'] = parsed_url.netloc
            
            streams.append(stream_data)
    
    return streams


def consume_activity_audit_events_v2(logger: logging.Logger, stream_data: Dict[str, Any], 
                                    last_event_time: int, stream_idx: int, 
                                    timeout: int = 60) -> Tuple[List[Dict[str, Any]], int]:
    """Consume Activity Audit events from a dataFeedURL with timestamp filtering."""
    if not stream_data.get('dataFeedURL'):
        logger.warning("No dataFeedURL provided")
        return [], last_event_time
        
    url = stream_data['dataFeedURL']
    
    # Build URL with timestamp filtering instead of offset
    # Start from beginning but filter events by eventCreationTime
    url_formed = f"{url}&whence=0"
    
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Add authorization if we have a session token
    if stream_data.get('sessionToken'):
        headers['Authorization'] = f"Token {stream_data['sessionToken']}"
    
    events = []
    latest_event_time = last_event_time
    start_time = time.time()
    
    try:
        logger.info(f"Connecting to event stream {stream_idx + 1}: {url_formed}")
        logger.info(f"Collecting events newer than {last_event_time} (timestamp in ms) for {timeout} seconds")
        
        # Stream events with timeout
        with requests.get(url_formed, headers=headers, stream=True, timeout=timeout+10) as response:
            if response.status_code >= 400:
                logger.error(f"Connection failed with status code: {response.status_code}")
                return events, latest_event_time
            
            logger.info(f"Connected successfully to stream {stream_idx + 1}, response code: {response.status_code}")
            
            # Process the stream line by line
            for line in response.iter_lines():
                # Check timeout - stop after specified seconds
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout:
                    logger.info(f"Timeout reached after {int(elapsed_time)} seconds, stopping collection")
                    break
                
                # Skip empty lines
                if not line:
                    continue
                
                try:
                    # Parse the JSON event
                    event = json.loads(line)
                    
                    # Extract metadata
                    metadata = event.get('metadata', {})
                    event_type = metadata.get('eventType', 'unknown')
                    event_creation_time = metadata.get('eventCreationTime')
                    
                    # Skip events that are older than our checkpoint
                    if event_creation_time and event_creation_time <= last_event_time:
                        logger.debug(f"Skipping old event: {event_type} at {event_creation_time} (checkpoint: {last_event_time})")
                        continue
                    
                    # Filter for Activity Audit events (any event ending in 'ActivityAuditEvent')
                    if is_activity_audit_event(event_type):
                        # Add TA metadata
                        event['ta_data'] = {
                            'stream_id': stream_idx + 1,
                            'event_type': event_type,
                            'addon_version': get_custom_user_agent(),
                            'collection_timestamp': datetime.utcnow().isoformat() + "Z"
                        }
                        
                        events.append(event)
                        
                        # Update latest event time
                        if event_creation_time and event_creation_time > latest_event_time:
                            latest_event_time = event_creation_time
                        
                        logger.debug(f"Processed {event_type} event at {event_creation_time}")
                    
                    else:
                        # Log non-matching events at debug level
                        logger.debug(f"Skipping non-Activity Audit event: {event_type}")
                
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON event: {e}")
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
    
    except requests.exceptions.Timeout:
        logger.error(f"Connection timed out for stream {stream_idx + 1}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for stream {stream_idx + 1}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error for stream {stream_idx + 1}: {str(e)}")
    
    logger.info(f"Completed streaming from stream {stream_idx + 1}, collected {len(events)} Activity Audit events")
    return events, latest_event_time


def consume_activity_audit_events(logger: logging.Logger, stream_data: Dict[str, Any], 
                                 last_offset: int, stream_idx: int, 
                                 timeout: int = 60) -> Tuple[List[Dict[str, Any]], int]:
    """Consume Activity Audit events from a dataFeedURL (legacy offset-based method)."""
    if not stream_data.get('dataFeedURL'):
        logger.warning("No dataFeedURL provided")
        return [], last_offset
        
    url = stream_data['dataFeedURL']
    
    # Build URL with offset and event type filtering
    if last_offset > 0:
        url_formed = f"{url}&offset={last_offset + 1}"
    else:
        url_formed = f"{url}&whence=0"  # Start from beginning
    
    # Add event type filtering for Activity Audit events
    # Note: We'll filter on the client side since we want any event ending in 'ActivityAuditEvent'
    # Server-side filtering would require listing all possible event types
    # url_formed += f"&eventType={event_types_str}"
    
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Add authorization if we have a session token
    if stream_data.get('sessionToken'):
        headers['Authorization'] = f"Token {stream_data['sessionToken']}"
    
    events = []
    latest_offset = last_offset
    start_time = time.time()
    
    try:
        logger.info(f"Connecting to event stream {stream_idx + 1}: {url_formed}")
        logger.info(f"Collecting events for {timeout} seconds")
        
        # Stream events with timeout
        with requests.get(url_formed, headers=headers, stream=True, timeout=timeout+10) as response:
            if response.status_code >= 400:
                logger.error(f"Connection failed with status code: {response.status_code}")
                return events, latest_offset
            
            logger.info(f"Connected successfully to stream {stream_idx + 1}, response code: {response.status_code}")
            
            # Process the stream line by line
            for line in response.iter_lines():
                # Check timeout - stop after specified seconds
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout:
                    logger.info(f"Timeout reached after {int(elapsed_time)} seconds, stopping collection")
                    break
                
                # Skip empty lines
                if not line:
                    continue
                
                try:
                    # Parse the JSON event
                    event = json.loads(line)
                    
                    # Extract metadata
                    metadata = event.get('metadata', {})
                    event_type = metadata.get('eventType', 'unknown')
                    offset_num = metadata.get('offset')
                    event_creation_time = metadata.get('eventCreationTime')
                    
                    # Filter for Activity Audit events (any event ending in 'ActivityAuditEvent')
                    if is_activity_audit_event(event_type):
                        # Add TA metadata
                        event['ta_data'] = {
                            'stream_id': stream_idx + 1,
                            'event_type': event_type,
                            'addon_version': get_custom_user_agent(),
                            'collection_timestamp': datetime.utcnow().isoformat() + "Z"
                        }
                        
                        events.append(event)
                        
                        # Update latest offset
                        if offset_num is not None and offset_num > latest_offset:
                            latest_offset = offset_num
                        
                        logger.debug(f"Processed {event_type} event at offset {offset_num}")
                    
                    else:
                        # Log non-matching events at debug level
                        logger.debug(f"Skipping non-Activity Audit event: {event_type}")
                
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON event: {e}")
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
    
    except requests.exceptions.Timeout:
        logger.error(f"Connection timed out for stream {stream_idx + 1}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for stream {stream_idx + 1}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error for stream {stream_idx + 1}: {str(e)}")
    
    logger.info(f"Completed streaming from stream {stream_idx + 1}, collected {len(events)} Activity Audit events")
    return events, latest_offset


def validate_input(definition: smi.ValidationDefinition):
    """Validate the input configuration."""
    # Basic validation - could be extended as needed
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    """
    Stream CrowdStrike Activity Audit data to Splunk
    
    This function retrieves Activity Audit events from CrowdStrike using APIHarnessV2 with EventStreams API:
    1. Get available event streams using list_available_streams via APIHarnessV2
    2. Connect to stream URLs and consume Activity Audit events with timestamp-based filtering
    3. Use eventCreationTime (milliseconds) for checkpointing instead of offset
    4. Default to 90 days ago for initial checkpoint (similar to XDR Alert helper)
    """
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        session_key = inputs.metadata["session_key"]
        logger = logger_for_input(session_key, normalized_input_name)
        
        try:
            # Configure logging
            log_level = get_log_level(session_key)
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)
            
            # Get account configuration
            account_name = input_item.get("account")
            if not account_name:
                logger.error("No account specified in input configuration")
                continue
                
            # Get cloud environment from input configuration
            cloud_env = input_item.get("cloud")
            if not cloud_env:
                logger.error("No cloud environment specified in input configuration")
                continue
                
            logger.debug(f"Retrieving credentials for account: {account_name}")
            client_id, client_secret = get_account_credentials(session_key, account_name)
            if not client_id or not client_secret:
                logger.error(f"No credentials found for account: {account_name}. "
                           f"Client ID present: {bool(client_id)}, Client Secret present: {bool(client_secret)}")
                logger.debug(f"Session key length: {len(session_key) if session_key else 0}")
                continue
            
            # Log credential validation (without exposing actual values)
            logger.debug(f"Credentials retrieved - Client ID length: {len(client_id)}, "
                        f"Client Secret length: {len(client_secret)}")
            
            # Basic validation of credential format
            if not client_id.strip() or not client_secret.strip():
                logger.error(f"Invalid credentials for account {account_name}: credentials contain only whitespace")
                continue
                
            # Get base URL from cloud environment
            base_url = get_base_url_from_cloud(cloud_env)
            logger.info(f"Using CrowdStrike base URL: {base_url} (cloud: {cloud_env})")
            
            # Handle checkpointing with timestamp-based approach
            checkpoint_name = f"{account_name}-{normalized_input_name}-activity-audit".replace("://", "_")
            checkpoint_valid, last_event_time = get_checkpoint(logger, session_key, checkpoint_name)
            
            if not checkpoint_valid:
                logger.error("Failed to retrieve checkpoint data")
                continue
            
            # Convert timestamp to readable format for logging
            last_event_datetime = datetime.fromtimestamp(last_event_time / 1000).isoformat() if last_event_time else "N/A"
            logger.info(f"Last checkpoint event time: {last_event_time} ms ({last_event_datetime})")
            
            # Get Activity Audit data using APIHarnessV2 with timestamp filtering
            logger.info("Starting CrowdStrike Activity Audit collection")
            logger.info(f"Collection parameters - Account: {account_name}, Cloud: {cloud_env}, Base URL: {base_url}")
            
            collection_start_time = time.time()
            audit_events = get_crowdstrike_activity_audit_data(
                logger=logger,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                last_event_time=last_event_time
            )
            collection_duration = time.time() - collection_start_time
            
            logger.info(f"Activity Audit collection completed in {collection_duration:.2f} seconds")
            
            if not audit_events:
                logger.warning("No Activity Audit events generated")
                continue
            
            # Find latest event time for checkpoint
            latest_event_time = last_event_time
            for event in audit_events:
                # Update checkpoint if this event has a newer timestamp
                event_time = event.get('ta_data', {}).get('latest_event_time', last_event_time)
                if event_time > latest_event_time:
                    latest_event_time = event_time
                
                # Also check the actual event metadata for eventCreationTime
                metadata = event.get('metadata', {})
                event_creation_time = metadata.get('eventCreationTime')
                if event_creation_time and event_creation_time > latest_event_time:
                    latest_event_time = event_creation_time
            
            # Send events to Splunk
            sourcetype = "crowdstrike:activity:audit:json"
            index = input_item.get("index", "default")
            
            try:
                logger.info(f"Sending {len(audit_events)} Activity Audit events to Splunk")
                logger.debug(f"Event destination - Index: {index}, Sourcetype: {sourcetype}")
                
                send_start_time = time.time()
                
                # Send events individually to maintain proper event boundaries
                events_sent = 0
                for event in audit_events:
                    # Use event creation time if available, otherwise current time
                    event_time = None
                    if 'metadata' in event and 'eventCreationTime' in event['metadata']:
                        event_time = event['metadata']['eventCreationTime'] / 1000
                    
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(event, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                            time=event_time
                        )
                    )
                    events_sent += 1
                    
                    # Log progress for large batches
                    if events_sent % 100 == 0:
                        logger.debug(f"Sent {events_sent}/{len(audit_events)} events to Splunk")
                
                send_duration = time.time() - send_start_time
                logger.info(f"Successfully sent {len(audit_events)} Activity Audit events to Splunk in {send_duration:.2f} seconds")
                
                # Update checkpoint after successful event processing
                if set_checkpoint(logger, session_key, checkpoint_name, latest_event_time):
                    latest_event_datetime = datetime.fromtimestamp(latest_event_time / 1000).isoformat() if latest_event_time else "N/A"
                    logger.info(f"Successfully updated checkpoint to event time: {latest_event_time} ms ({latest_event_datetime})")
                else:
                    logger.warning("Failed to update checkpoint")
                
                # Log ingestion details
                log.events_ingested(
                    logger,
                    input_name,
                    sourcetype,
                    len(audit_events),
                    index,
                    account=account_name,
                )
                
            except Exception as send_error:
                logger.error(f"Failed to send events to Splunk: {send_error}")
                logger.debug(f"Send error details: {send_error}", exc_info=True)
            
            log.modular_input_end(logger, normalized_input_name)
            
        except Exception as e:
            logger.error(f"Exception in Activity Audit collection for {normalized_input_name}: {e}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.debug(f"Full exception details for {normalized_input_name}: {e}", exc_info=True)
            
            # Log additional context if available
            try:
                logger.error(f"Exception context - Account: {account_name if 'account_name' in locals() else 'Unknown'}, "
                           f"Cloud: {cloud_env if 'cloud_env' in locals() else 'Unknown'}, "
                           f"Base URL: {base_url if 'base_url' in locals() else 'Unknown'}")
            except:
                pass
            
            log.log_exception(
                logger, 
                e, 
                "activity_audit_collection_error", 
                msg_before=f"Exception raised while collecting Activity Audit events for {normalized_input_name}: "
            )