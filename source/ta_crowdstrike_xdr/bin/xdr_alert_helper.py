import json
import logging
import time
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

import import_declare_test
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi
import crowdstrike_constants as const

try:
    from falconpy import Alerts
except ImportError:
    Alerts = None


ADDON_NAME = "ta_crowdstrike_xdr"
CHECKPOINTER_NAME = "ta_crowdstrike_xdr_checkpoints"


class StatusCodeErrors:
    """Enhanced status code error handling for CrowdStrike API responses"""
    
    @staticmethod
    def handle_status_code_errors(response: Dict[str, Any], api_endpoint: str, log_label: str, logger: logging.Logger) -> Dict[str, Any]:
        """
        Handle status code errors from CrowdStrike API responses with enhanced logging
        
        Args:
            response: API response dictionary
            api_endpoint: Name of the API endpoint that was called
            log_label: Label for logging context
            logger: Logger instance
            
        Returns:
            Dictionary containing error event data for Splunk
        """
        status_code = response.get('status_code')
        logger.info(f"{log_label}: Response code from the {api_endpoint} = {status_code}")
        
        # Initialize error event structure
        error_event = {
            "timestamp": time.time(),
            "status": "critical",
            "api_endpoint": api_endpoint,
            "error_details": {
                "status_code": status_code,
                "log_label": log_label
            }
        }
        
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
                    error_event["error_details"]["trace_id"] = cs_traceid
                
                logger.error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
                error_event["message"] = f"CrowdStrike API client error (4xx): {cs_error_msg}"
                error_event["error_details"]["error_message"] = cs_error_msg
                error_event["error_details"]["error_type"] = "client_error"
                
            elif status_code_str.startswith('50'):
                # 5xx Server Errors
                cs_error_msg = "Unknown server error"
                
                # Extract error message from response body
                if 'body' in response and isinstance(response['body'], dict):
                    errors = response['body'].get('errors', [])
                    if errors and isinstance(errors, list) and len(errors) > 0:
                        cs_error_msg = errors[0].get('message', cs_error_msg)
                
                logger.error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
                error_event["message"] = f"CrowdStrike API server error (5xx): {cs_error_msg}"
                error_event["error_details"]["error_message"] = cs_error_msg
                error_event["error_details"]["error_type"] = "server_error"
                
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
                    error_event["error_details"]["trace_id"] = cs_traceid
                
                logger.error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
                error_event["message"] = f"CrowdStrike API error ({status_code}): {cs_error_msg}"
                error_event["error_details"]["error_message"] = cs_error_msg
                error_event["error_details"]["error_type"] = "other_error"
        
        except Exception as parse_error:
            # If we can't parse the error response, log what we can
            logger.error(f"{log_label}: Failed to parse error response: {parse_error}")
            error_event["message"] = f"CrowdStrike API error ({status_code}) - failed to parse error details"
            error_event["error_details"]["parse_error"] = str(parse_error)
            error_event["error_details"]["raw_response"] = str(response)
        
        # Add full response for debugging if debug logging is enabled
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"{log_label}: Full API response: {response}")
            error_event["error_details"]["full_response"] = response
        
        logger.error(f"{log_label}: API call failed, continuing with error handling")
        
        return error_event


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


def get_checkpoint(logger: logging.Logger, session_key: str, checkpoint_name: str) -> Tuple[bool, Optional[str]]:
    """
    Get checkpoint data from KVStore
    
    Args:
        logger: Logger instance
        session_key: Splunk session key
        checkpoint_name: Name of the checkpoint
        
    Returns:
        Tuple of (success, checkpoint_value)
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, ADDON_NAME
        )
        checkpoint_data = checkpoint_collection.get(checkpoint_name)
        if checkpoint_data:
            return True, checkpoint_data.get("updated_timestamp")
        else:
            # Default to 30 days ago if no checkpoint exists
            default_time = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
            return True, default_time
    except Exception as e:
        logger.error(f"Error retrieving checkpoint: {e}")
        return False, None


def set_checkpoint(logger: logging.Logger, session_key: str, checkpoint_name: str, checkpoint_value: str) -> bool:
    """
    Set checkpoint data in KVStore
    
    Args:
        logger: Logger instance
        session_key: Splunk session key
        checkpoint_name: Name of the checkpoint
        checkpoint_value: Value to store
        
    Returns:
        Success status
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, ADDON_NAME
        )
        checkpoint_collection.update(checkpoint_name, {'updated_timestamp': checkpoint_value})
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


def get_base_url_from_settings(session_key: str, account_name: str) -> str:
    """
    Get the CrowdStrike base URL from settings or account configuration (legacy function)
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_crowdstrike_xdr_account",
        )
        account_conf_file = cfm.get_conf("ta_crowdstrike_xdr_account")
        account_config = account_conf_file.get(account_name)
        
        # Check if base_url is configured in account
        base_url = account_config.get("base_url")
        if base_url:
            return base_url
            
        # Check cloud environment setting
        cloud_env = account_config.get("cloud_environment", "us_commercial")
        
        # Map cloud environment to base URL
        cloud_mapping = {
            "us_commercial": const.us_commercial_base,
            "us_commercial2": const.us_commercial2_base,
            "govcloud": const.govcloud_base,
            "eucloud": const.eucloud_base
        }
        
        return cloud_mapping.get(cloud_env, const.us_commercial_base)
        
    except Exception:
        # Default to US Commercial if settings can't be retrieved
        return const.us_commercial_base


def get_crowdstrike_alerts_data(logger: logging.Logger, client_id: str, client_secret: str, 
                               base_url: str, last_checkpoint: str) -> List[Dict[str, Any]]:
    """
    Get CrowdStrike alerts data using AlertsV2 service collection
    
    Args:
        logger: Logger instance
        client_id: CrowdStrike client ID
        client_secret: CrowdStrike client secret
        base_url: CrowdStrike base URL
        last_checkpoint: Last checkpoint timestamp
        
    Returns:
        List of alert events for Splunk
    """
    if Alerts is None:
        logger.error("FalconPy SDK not available. Please install falconpy package.")
        return [{
            "timestamp": time.time(),
            "status": "critical",
            "message": "FalconPy SDK not available - cannot retrieve alerts",
            "error_details": {"error": "Missing falconpy dependency"}
        }]
    
    logger.info(f"Retrieving CrowdStrike alerts from: {base_url}")
    
    try:
        # Initialize the Alerts service collection
        falcon = Alerts(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        
        # Step 1: Query alert IDs using V2 API
        logger.info("Step 1: Querying alert IDs using AlertsV2")
        log_api_operation_start(
            logger=logger,
            api_endpoint="query_alerts_v2",
            operation="Query alert IDs with time filter",
            base_url=base_url,
            client_id_length=len(client_id) if client_id else 0,
            last_checkpoint=last_checkpoint
        )
        
        limit = 10000
        sort = "updated_timestamp.asc"
        time_filter = f"updated_timestamp:>='{last_checkpoint}'"
        
        logger.debug(f"Alert filter: {time_filter}")
        logger.debug(f"Query parameters - Limit: {limit}, Sort: {sort}")
        
        alert_id_response = falcon.query_alerts_v2(
            limit=limit, 
            filter=time_filter, 
            sort=sort
        )
        
        if alert_id_response.get("status_code") not in [200, 201]:
            # Use enhanced error handling
            log_label = "Alert ID Query"
            error_event = StatusCodeErrors.handle_status_code_errors(
                response=alert_id_response,
                api_endpoint="query_alerts_v2",
                log_label=log_label,
                logger=logger
            )
            
            # Add additional context for authentication errors
            if alert_id_response.get("status_code") == 401:
                error_event["error_details"]["authentication_error"] = True
                error_event["error_details"]["base_url"] = base_url
                error_event["error_details"]["client_id_length"] = len(client_id) if client_id else 0
                error_event["error_details"]["client_secret_length"] = len(client_secret) if client_secret else 0
            
            # Add query context
            error_event["error_details"]["query_context"] = {
                "time_filter": time_filter,
                "limit": limit,
                "sort": sort,
                "last_checkpoint": last_checkpoint
            }
            
            return [error_event]
        
        alert_ids = alert_id_response.get("body", {}).get("resources", [])
        logger.info(f"Step 1 completed: Found {len(alert_ids)} alert IDs")
        log_api_operation_success(
            logger=logger,
            api_endpoint="query_alerts_v2",
            operation="Query alert IDs with time filter",
            result_count=len(alert_ids),
            time_filter=time_filter
        )
        
        if not alert_ids:
            logger.info("No new alerts found")
            return [{
                "timestamp": time.time(),
                "status": "info",
                "message": "No new alerts found in CrowdStrike",
                "alert_count": 0
            }]
        
        # Step 2: Get alert details in chunks using V2 API
        logger.info("Step 2: Fetching alert details using AlertsV2")
        log_api_operation_start(
            logger=logger,
            api_endpoint="get_alerts_v2",
            operation="Fetch alert details in chunks",
            total_alerts=len(alert_ids),
            expected_chunks=(len(alert_ids) + 999) // 1000
        )
        
        all_alerts = []
        details_query_limit = 1000
        chunk_count = 0
        
        for i in range(0, len(alert_ids), details_query_limit):
            chunk_count += 1
            chunk = alert_ids[i:i + details_query_limit]
            logger.debug(f"Fetching details for chunk {chunk_count} ({len(chunk)} alerts)")
            
            detail_result = falcon.get_alerts_v2(ids=chunk)
            
            if detail_result.get("status_code") not in [200, 201]:
                # Use enhanced error handling
                log_label = f"Alert Details (Chunk {chunk_count})"
                error_event = StatusCodeErrors.handle_status_code_errors(
                    response=detail_result,
                    api_endpoint="get_alerts_v2",
                    log_label=log_label,
                    logger=logger
                )
                
                # Add chunk context
                error_event["error_details"]["chunk_context"] = {
                    "chunk_number": chunk_count,
                    "chunk_size": len(chunk),
                    "alert_ids_in_chunk": chunk[:10],  # Only log first 10 IDs to avoid log bloat
                    "total_chunks": (len(alert_ids) + 999) // 1000,
                    "alerts_processed_so_far": len([a for a in all_alerts if 'alert_id' in a])
                }
                
                # Continue with other chunks but record the error
                all_alerts.append(error_event)
                continue
            
            if "resources" in detail_result.get("body", {}):
                alerts_in_chunk = detail_result["body"]["resources"]
                all_alerts.extend(alerts_in_chunk)
                logger.debug(f"Retrieved {len(alerts_in_chunk)} alert details")
        
        successful_alert_details = len([a for a in all_alerts if 'alert_id' in a])
        logger.info(f"Step 2 completed: Retrieved details for {successful_alert_details} alerts")
        log_api_operation_success(
            logger=logger,
            api_endpoint="get_alerts_v2",
            operation="Fetch alert details in chunks",
            result_count=successful_alert_details,
            chunks_processed=chunk_count,
            total_alerts_requested=len(alert_ids)
        )
        
        # Convert alerts to Splunk events and add TA metadata
        alert_events = []
        latest_timestamp = last_checkpoint
        
        for alert in all_alerts:
            # Skip error events (they don't have 'alert_id' field)
            if 'alert_id' not in alert:
                alert_events.append(alert)  # These are already formatted as error events
                continue
            
            # Track the latest timestamp for checkpointing
            if alert.get('updated_timestamp', '') > latest_timestamp:
                latest_timestamp = alert['updated_timestamp']
            
            # Add the alert as-is (CrowdStrike alerts are already well-structured)
            alert_events.append(alert)
        
        # Add summary event
        successful_alerts = len([e for e in alert_events if 'alert_id' in e])
        error_count = len([e for e in alert_events if e.get("status") == "critical"])
        
        summary_event = {
            "timestamp": time.time(),
            "status": "healthy" if error_count == 0 else "warning",
            "message": f"Alert collection completed: {successful_alerts} alerts retrieved, {error_count} errors",
            "summary": True,
            "total_alerts": len(alert_ids),
            "successful_retrievals": successful_alerts,
            "error_count": error_count,
            "collection_time": datetime.utcnow().isoformat(),
            "latest_timestamp": latest_timestamp
        }
        
        alert_events.insert(0, summary_event)  # Add summary as first event
        
        logger.info(f"Alert data collection completed: {len(alert_events)} events generated")
        return alert_events
        
    except Exception as e:
        logger.error(f"Exception while retrieving alerts: {e}")
        return [{
            "timestamp": time.time(),
            "status": "critical",
            "message": f"Exception while retrieving alerts: {str(e)}",
            "error_details": {"exception": str(e)}
        }]


def validate_input(definition: smi.ValidationDefinition):
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    """
    Stream CrowdStrike alert data to Splunk
    
    This function retrieves alerts from CrowdStrike using the 2-step process:
    1. Query alert IDs using GetQueriesAlertsV1
    2. Get full alert details using PostEntitiesAlertsV1
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
            
            # Handle checkpointing
            checkpoint_name = f"{account_name}-{normalized_input_name}-alerts".replace("://", "_")
            checkpoint_valid, last_checkpoint = get_checkpoint(logger, session_key, checkpoint_name)
            
            if not checkpoint_valid:
                logger.error("Failed to retrieve checkpoint data")
                continue
                
            current_run_time = datetime.utcnow().isoformat() + "Z"
            logger.info(f"Last checkpoint: {last_checkpoint}, Current run time: {current_run_time}")
            
            # Get alerts data using AlertsV2 service collection
            logger.info("Starting CrowdStrike alert collection")
            logger.info(f"Collection parameters - Account: {account_name}, Cloud: {cloud_env}, Base URL: {base_url}")
            
            collection_start_time = time.time()
            alert_events = get_crowdstrike_alerts_data(
                logger=logger,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                last_checkpoint=last_checkpoint
            )
            collection_duration = time.time() - collection_start_time
            
            logger.info(f"Alert collection completed in {collection_duration:.2f} seconds")
            
            if not alert_events:
                logger.warning("No alert events generated")
                continue
            
            # Prepare TA metadata for each event
            ta_data = {
                "addon_name": ADDON_NAME,
                "addon_version": "0.0.1",
                "account": account_name,
                "base_url": base_url,
                "input_name": normalized_input_name,
                "collection_time": datetime.utcnow().isoformat()
            }
            
            # Add TA data to each event and find latest timestamp for checkpoint
            latest_timestamp = last_checkpoint
            for event in alert_events:
                event['ta_data'] = ta_data
                # Update checkpoint if this event has a newer timestamp
                if event.get('updated_timestamp', '') > latest_timestamp:
                    latest_timestamp = event['updated_timestamp']
            
            # Send events to Splunk
            sourcetype = "crowdstrike:unified:alert:json"
            index = input_item.get("index", "default")
            
            try:
                logger.info(f"Sending {len(alert_events)} alert events to Splunk")
                logger.debug(f"Event destination - Index: {index}, Sourcetype: {sourcetype}")
                
                # Count different event types for logging
                event_types = {}
                for event in alert_events:
                    if 'alert_id' in event:
                        event_types['alerts'] = event_types.get('alerts', 0) + 1
                    elif event.get('summary'):
                        event_types['summary'] = event_types.get('summary', 0) + 1
                    else:
                        event_status = event.get("status", "unknown")
                        event_types[event_status] = event_types.get(event_status, 0) + 1
                
                logger.info(f"Event breakdown: {dict(event_types)}")
                
                send_start_time = time.time()
                
                # Send events individually to maintain proper event boundaries
                events_sent = 0
                for event in alert_events:
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(event, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                        )
                    )
                    events_sent += 1
                    
                    # Log progress for large batches
                    if events_sent % 100 == 0:
                        logger.debug(f"Sent {events_sent}/{len(alert_events)} events to Splunk")
                
                send_duration = time.time() - send_start_time
                logger.info(f"Successfully sent {len(alert_events)} alert events to Splunk in {send_duration:.2f} seconds")
                
                # Update checkpoint after successful event processing
                if set_checkpoint(logger, session_key, checkpoint_name, latest_timestamp):
                    logger.info(f"Successfully updated checkpoint to: {latest_timestamp}")
                else:
                    logger.warning("Failed to update checkpoint")
                
                # Log ingestion details
                log.events_ingested(
                    logger,
                    input_name,
                    sourcetype,
                    len(alert_events),
                    index,
                    account=account_name,
                )
                
            except Exception as send_error:
                logger.error(f"Failed to send events to Splunk: {send_error}")
                # Create error event
                error_event = {
                    "timestamp": time.time(),
                    "status": "critical",
                    "message": f"Failed to send alert events to Splunk: {str(send_error)}",
                    "error_details": {"exception": str(send_error)},
                    "ta_data": ta_data
                }
                
                # Try to send error event directly
                try:
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(error_event, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                        )
                    )
                except Exception as error_send_exception:
                    logger.error(f"Failed to send error event: {error_send_exception}")
            
            log.modular_input_end(logger, normalized_input_name)
            
        except Exception as e:
            logger.error(f"Exception in alert collection for {normalized_input_name}: {e}")
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
                "alert_collection_error", 
                msg_before=f"Exception raised while collecting alerts for {normalized_input_name}: "
            )
            
            # Try to send exception as event
            try:
                error_event = {
                    "timestamp": time.time(),
                    "status": "critical",
                    "message": f"Alert collection exception: {str(e)}",
                    "error_details": {"exception": str(e), "input_name": normalized_input_name}
                }
                
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(error_event, ensure_ascii=False, default=str),
                        index=input_item.get("index", "default"),
                        sourcetype="crowdstrike:alerts",
                    )
                )
            except Exception:
                # If we can't even send the error event, just log it
                logger.error("Failed to send exception event to Splunk")