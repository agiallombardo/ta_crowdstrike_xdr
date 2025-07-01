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
    from falconpy import APIHarnessV2, PreventionPolicy
    from falconpy._constant import USER_AGENT as FALCONPY_USER_AGENT
except ImportError:
    APIHarnessV2 = None
    PreventionPolicy = None
    FALCONPY_USER_AGENT = None


ADDON_NAME = "ta_crowdstrike_xdr"
CHECKPOINTER_NAME = "ta_crowdstrike_xdr_checkpoints"


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
    
    Logs are stored in $SPLUNK_HOME/var/log/splunk/ta_msft_sec_xdr_*.log
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
            return True, checkpoint_data.get("last_run_time")
        else:
            # Default to 90 days ago if no checkpoint exists
            default_time = (datetime.utcnow() - timedelta(days=90)).isoformat() + "Z"
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
        checkpoint_collection.update(checkpoint_name, {'last_run_time': checkpoint_value})
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


def get_prevention_policies_data_v2(logger: logging.Logger, client_id: str, client_secret: str, 
                                   base_url: str = None, max_retries: int = 3) -> List[Dict[str, Any]]:
    """
    Get CrowdStrike prevention policies data using APIHarnessV2 with enhanced authentication
    
    Args:
        logger: Logger instance
        client_id: CrowdStrike Client ID
        client_secret: CrowdStrike Client Secret
        base_url: CrowdStrike base URL (optional, defaults to US Commercial)
        max_retries: Maximum number of retry attempts for authentication failures
        
    Returns:
        List of prevention policy events for Splunk
    """
    if not APIHarnessV2:
        logger.error("FalconPy SDK APIHarnessV2 not available - cannot retrieve prevention policies")
        return []
    
    # Use default base URL if not provided
    if not base_url:
        base_url = const.us_commercial_base
        
    logger.info(f"Retrieving CrowdStrike prevention policies from: {base_url} using APIHarnessV2")
    
    # Validate credentials
    if not client_id or not client_secret:
        logger.error("Missing CrowdStrike credentials")
        return []
    
    # Clean credentials - remove any whitespace
    client_id = client_id.strip()
    client_secret = client_secret.strip()
    
    # Log credential info for debugging (without exposing actual values)
    logger.info(f"Authentication Debug - Client ID length: {len(client_id)}, Client Secret length: {len(client_secret)}")
    logger.info(f"Authentication Debug - Base URL: {base_url}")
    
    # Retry logic for authentication failures
    for attempt in range(max_retries):
        try:
            logger.debug(f"Authentication attempt {attempt + 1} of {max_retries}")
            
            # Initialize the APIHarnessV2 with Direct Authentication
            # Based on falconpy tests, we should NOT use context manager for direct auth
            falcon = APIHarnessV2(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                debug=logger.level <= logging.DEBUG,
                proxy={},  # Empty proxy dict to ensure no proxy issues
                user_agent=get_custom_user_agent()
            )
            
            logger.info(f"Successfully created CrowdStrike API client (attempt {attempt + 1})")
            
            # The APIHarnessV2 with client credentials should authenticate automatically on first API call
            # Let's make the API call directly without explicit authentication
            logger.info("Step 1: Querying all prevention policy IDs")
            log_api_operation_start(
                logger=logger,
                api_endpoint="queryCombinedPreventionPolicies",
                operation="Query all prevention policy IDs",
                base_url=base_url,
                client_id_length=len(client_id) if client_id else 0,
                last_checkpoint="N/A"
            )
            
            # Make the API call - authentication happens automatically
            policy_response = falcon.command(
                action="queryCombinedPreventionPolicies",
                filter="platform_name:'Windows'+platform_name:'Mac'+platform_name:'Linux'"
            )
            
            # Check if we got a response
            if not policy_response:
                logger.error(f"No response received from API call on attempt {attempt + 1}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    logger.error("No response received from CrowdStrike API")
                    return []
            
            # Check for authentication errors
            status_code = policy_response.get("status_code", 0)
            logger.debug(f"API response status code: {status_code}")
            
            if status_code == 401:
                logger.warning(f"Received 401 authentication error on attempt {attempt + 1}")
                
                # Log more details about the 401 error
                if policy_response.get("body"):
                    errors = policy_response.get("body", {}).get("errors", [])
                    if errors:
                        logger.error(f"Authentication error details: {errors}")
                
                if attempt < max_retries - 1:
                    logger.info("Authentication error - will retry...")
                    time.sleep(2)
                    continue
                else:
                    log_label = "Prevention Policy Query"
                    StatusCodeErrors.handle_status_code_errors(
                        response=policy_response,
                        api_endpoint="queryCombinedPreventionPolicies",
                        log_label=log_label,
                        logger=logger
                    )
                    logger.error(f"{log_label}: Authentication error - max retries exceeded")
                    logger.error(f"{log_label}: Troubleshooting steps:")
                    logger.error(f"{log_label}: - Verify Client ID and Client Secret are correct")
                    logger.error(f"{log_label}: - Ensure credentials are for the correct CrowdStrike environment")
                    logger.error(f"{log_label}: - Current base URL: {base_url}")
                    logger.error(f"{log_label}: - Check if credentials have been rotated or expired")
                    logger.error(f"{log_label}: - Verify API client has required scopes (prevention-policies:read)")
                    logger.error(f"{log_label}: - Ensure no extra whitespace or special characters in credentials")
                    return []
            
            if status_code not in [200, 201]:
                log_label = "Prevention Policy Query"
                StatusCodeErrors.handle_status_code_errors(
                    response=policy_response,
                    api_endpoint="queryCombinedPreventionPolicies",
                    log_label=log_label,
                    logger=logger
                )
                return []
            
            # Success! Extract policies
            policies = policy_response.get("body", {}).get("resources", [])
            # Handle case where resources is None
            if policies is None:
                policies = []
            logger.info(f"Step 1 completed: Found {len(policies)} prevention policies")
            log_api_operation_success(
                logger=logger,
                api_endpoint="queryCombinedPreventionPolicies",
                operation="Query all prevention policy IDs",
                result_count=len(policies),
                time_filter="N/A"
            )
            
            if not policies:
                logger.info("No prevention policies found")
                return []
            
            # If we need to get more details, we would make additional API calls here
            # For now, return the policies we found
            return policies
            
        except Exception as e:
            logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
            logger.debug(f"Full exception details: {e}", exc_info=True)
            
            if attempt < max_retries - 1:
                logger.info(f"Retrying after unexpected error in 5 seconds...")
                time.sleep(5)
                continue
            else:
                logger.error(f"Unexpected error after {max_retries} attempts: {str(e)}")
                logger.error(f"Exception type: {type(e).__name__}")
                logger.error(f"Base URL: {base_url}")
                logger.error("Troubleshooting steps:")
                logger.error("- Check network connectivity to CrowdStrike API")
                logger.error("- Verify no firewall or proxy blocking connections")
                logger.error("- Ensure FalconPy library is up to date")
                logger.error("- Check system time is synchronized (for token generation)")
                return []
    
    logger.error("Authentication retry loop completed without success")
    return []






def get_prevention_policies_data(logger: logging.Logger, client_id: str, client_secret: str, base_url: str = None) -> List[Dict[str, Any]]:
    """
    Get CrowdStrike prevention policies data using the best available FalconPy method
    
    Args:
        logger: Logger instance
        client_id: CrowdStrike Client ID
        client_secret: CrowdStrike Client Secret
        base_url: CrowdStrike base URL (optional, defaults to US Commercial)
        
    Returns:
        List of prevention policy events for Splunk
    """
    # Try the new APIHarnessV2 method first (recommended)
    if APIHarnessV2:
        logger.info("Using enhanced APIHarnessV2 authentication method")
        return get_prevention_policies_data_v2(logger, client_id, client_secret, base_url)
    
    # Fallback to legacy method if APIHarnessV2 is not available
    logger.warning("APIHarnessV2 not available, falling back to legacy PreventionPolicy service class")
    
    if PreventionPolicy is None:
        logger.error("FalconPy SDK not available. Please install falconpy package.")
        return []
    
    # Use default base URL if not provided
    if not base_url:
        base_url = const.us_commercial_base
        
    logger.info(f"Retrieving CrowdStrike prevention policies from: {base_url} using legacy PreventionPolicy service class")
    
    # Validate credentials
    if not client_id or not client_secret:
        logger.error("Missing CrowdStrike credentials")
        return []
    
    # Log credential validation for debugging (without exposing values)
    logger.debug(f"Validating credentials - Client ID length: {len(client_id)}, "
                f"Client Secret length: {len(client_secret)}, Base URL: {base_url}")
    
    try:
        # Initialize the Prevention Policy API client
        logger.debug(f"Initializing CrowdStrike PreventionPolicy client with base_url: {base_url}")
        falcon = PreventionPolicy(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        
        # Log successful client initialization
        logger.debug("PreventionPolicy client initialized successfully")
        
        logger.info("Step 1: Querying all prevention policy IDs")
        log_api_operation_start(
            logger=logger,
            api_endpoint="query_combined_policies",
            operation="Query all prevention policy IDs",
            base_url=base_url,
            client_id_length=len(client_id) if client_id else 0
        )
        
        # Step 1: Query all policy IDs (with pagination)
        policy_ids = []
        offset = None
        page_count = 0
        
        while True:
            page_count += 1
            params = {"limit": 100}
            if offset:
                params["offset"] = offset
                
            logger.debug(f"Fetching policy IDs page {page_count} (offset: {offset})")
            
            result = falcon.query_combined_policies(parameters=params)
            
            if result.get("status_code") not in [200, 201]:
                # Use enhanced error handling
                log_label = f"Prevention Policy Query (Page {page_count})"
                StatusCodeErrors.handle_status_code_errors(
                    response=result,
                    api_endpoint="query_combined_policies",
                    log_label=log_label,
                    logger=logger
                )
                
                # Log additional context for authentication errors
                if result.get("status_code") == 401:
                    logger.error(f"{log_label}: Authentication error - base_url: {base_url}")
                    logger.error(f"{log_label}: Client ID length: {len(client_id) if client_id else 0}")
                    logger.error(f"{log_label}: Client secret length: {len(client_secret) if client_secret else 0}")
                
                # Log pagination context
                logger.error(f"{log_label}: Pagination context - page {page_count}, offset: {offset}")
                logger.error(f"{log_label}: Total policies found so far: {len(policy_ids)}")
                
                return []
            
            if "resources" in result and result["resources"]:
                new_ids = [r["id"] for r in result["resources"]]
                policy_ids.extend(new_ids)
                logger.debug(f"Found {len(new_ids)} policy IDs in page {page_count}")
            
            # Break if there's no more data
            pagination = result.get("meta", {}).get("pagination", {})
            if not pagination.get("nextOffset"):
                break
            offset = pagination["nextOffset"]
        
        logger.info(f"Step 1 completed: Found {len(policy_ids)} total prevention policies")
        log_api_operation_success(
            logger=logger,
            api_endpoint="query_combined_policies",
            operation="Query all prevention policy IDs",
            result_count=len(policy_ids),
            pages_processed=page_count
        )
        
        if not policy_ids:
            logger.warning("No prevention policies found")
            return []
        
        logger.info("Step 2: Fetching full policy details with settings")
        log_api_operation_start(
            logger=logger,
            api_endpoint="get_policies",
            operation="Fetch full policy details with settings",
            total_policies=len(policy_ids),
            expected_chunks=(len(policy_ids) + 99) // 100
        )
        
        # Step 2: Fetch full settings for those policies (in chunks of 100)
        all_policies = []
        chunk_count = 0
        
        for i in range(0, len(policy_ids), 100):
            chunk_count += 1
            chunk = policy_ids[i:i + 100]
            logger.debug(f"Fetching policy details chunk {chunk_count} ({len(chunk)} policies)")
            
            detail_result = falcon.get_policies(ids=chunk)
            
            if detail_result.get("status_code") not in [200, 201]:
                # Use enhanced error handling
                log_label = f"Prevention Policy Details (Chunk {chunk_count})"
                StatusCodeErrors.handle_status_code_errors(
                    response=detail_result,
                    api_endpoint="get_policies",
                    log_label=log_label,
                    logger=logger
                )
                
                # Log chunk context
                logger.error(f"{log_label}: Chunk context - chunk {chunk_count} of {(len(policy_ids) + 99) // 100}")
                logger.error(f"{log_label}: Chunk size: {len(chunk)}")
                logger.debug(f"{log_label}: Policy IDs in chunk: {chunk}")
                
                # Continue with other chunks
                continue
            
            if "resources" in detail_result:
                policies_in_chunk = detail_result["resources"]
                # Handle case where resources is None
                if policies_in_chunk is None:
                    policies_in_chunk = []
                all_policies.extend(policies_in_chunk)
                logger.debug(f"Retrieved {len(policies_in_chunk)} policy details in chunk {chunk_count}")
        
        successful_policy_details = len([p for p in all_policies if 'name' in p])
        logger.info(f"Step 2 completed: Retrieved details for {successful_policy_details} policies")
        log_api_operation_success(
            logger=logger,
            api_endpoint="get_policies",
            operation="Fetch full policy details with settings",
            result_count=successful_policy_details,
            chunks_processed=chunk_count,
            total_policies_requested=len(policy_ids)
        )
        
        # Return policies as-is (raw policy data)
        policy_events = []
        
        for policy in all_policies:
            # Only include valid policies (skip any error entries)
            if 'name' in policy:
                # Add the policy as-is (CrowdStrike policies are already well-structured)
                policy_events.append(policy)
        
        # Log collection summary
        successful_policies = len(policy_events)
        
        logger.info(f"Prevention policy collection completed: {successful_policies} policies retrieved")
        logger.info(f"Total policies requested: {len(policy_ids)}")
        
        logger.info(f"Prevention policy data collection completed: {len(policy_events)} events generated")
        return policy_events
        
    except Exception as e:
        logger.error(f"Exception while retrieving prevention policies: {e}")
        logger.debug(f"Full exception details: {e}", exc_info=True)
        return []


def validate_input(definition: smi.ValidationDefinition):
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    """
    Stream CrowdStrike prevention policy data to Splunk
    
    This function retrieves all prevention policies from CrowdStrike using the 2-step process:
    1. Query all policy IDs using query_combined_policies
    2. Get full policy details including settings using get_policies
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
                
            # Get credentials from account configuration
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
            checkpoint_name = f"{account_name}-{normalized_input_name}-last_runtime".replace("://", "_")
            checkpoint_valid, last_run_time = get_checkpoint(logger, session_key, checkpoint_name)
            
            if not checkpoint_valid:
                logger.error("Failed to retrieve checkpoint data")
                continue
                
            current_run_time = datetime.utcnow().isoformat() + "Z"
            logger.info(f"Last run time: {last_run_time}, Current run time: {current_run_time}")
            
            # Get prevention policies data using the 2-step process
            logger.info("Starting CrowdStrike prevention policy collection")
            logger.info(f"Collection parameters - Account: {account_name}, Cloud: {cloud_env}, Base URL: {base_url}")
            
            collection_start_time = time.time()
            policy_events = get_prevention_policies_data(
                logger=logger,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url
            )
            collection_duration = time.time() - collection_start_time
            
            logger.info(f"Prevention policy collection completed in {collection_duration:.2f} seconds")
            
            if not policy_events:
                logger.warning("No prevention policy events generated")
                continue
            
            # Events are sent as-is without additional metadata
            
            # Send events to Splunk
            sourcetype = "crowdstrike:prevention_policies:json"
            index = input_item.get("index", "default")
            
            try:
                logger.info(f"Sending {len(policy_events)} prevention policy events to Splunk")
                logger.debug(f"Event destination - Index: {index}, Sourcetype: {sourcetype}")
                
                send_start_time = time.time()
                
                # Send events individually to maintain proper event boundaries
                events_sent = 0
                for event in policy_events:
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(event, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                        )
                    )
                    events_sent += 1
                    
                    # Log progress for large batches
                    if events_sent % 50 == 0:
                        logger.debug(f"Sent {events_sent}/{len(policy_events)} events to Splunk")
                
                send_duration = time.time() - send_start_time
                logger.info(f"Successfully sent {len(policy_events)} prevention policy events to Splunk in {send_duration:.2f} seconds")
                
                # Update checkpoint after successful event processing
                if set_checkpoint(logger, session_key, checkpoint_name, current_run_time):
                    logger.info(f"Successfully updated checkpoint to: {current_run_time}")
                else:
                    logger.warning("Failed to update checkpoint")
                
                # Log ingestion details
                log.events_ingested(
                    logger,
                    input_name,
                    sourcetype,
                    len(policy_events),
                    index,
                    account=account_name,
                )
                
            except Exception as send_error:
                logger.error(f"Failed to send events to Splunk: {send_error}")
                logger.debug(f"Send error details: {send_error}", exc_info=True)
            
            log.modular_input_end(logger, normalized_input_name)
            
        except Exception as e:
            logger.error(f"Exception in prevention policy collection for {normalized_input_name}: {e}")
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
                "prevention_policy_error", 
                msg_before=f"Exception raised while collecting prevention policies for {normalized_input_name}: "
            )
            
            # Exception details are already logged above via log.log_exception
