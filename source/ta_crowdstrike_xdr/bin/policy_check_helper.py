import json
import logging
import time
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

import import_declare_test
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi
import crowdstrike_constants as const

try:
    from falconpy import PreventionPolicy
except ImportError:
    PreventionPolicy = None


ADDON_NAME = "ta_crowdstrike_xdr"
CHECKPOINTER_NAME = "ta_crowdstrike_xdr_checkpoints"

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


def get_account_api_key(session_key: str, account_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_crowdstrike_xdr_account",
    )
    account_conf_file = cfm.get_conf("ta_crowdstrike_xdr_account")
    return account_conf_file.get(account_name).get("api_key")


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
        checkpoint_collection.update(checkpoint_name, {'last_run_time': checkpoint_value})
        return True
    except Exception as e:
        logger.error(f"Error setting checkpoint: {e}")
        return False


def get_base_url_from_settings(session_key: str, account_name: str) -> str:
    """
    Get the CrowdStrike base URL from settings or account configuration
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


def get_prevention_policies_data(logger: logging.Logger, api_key: str, base_url: str = None) -> List[Dict[str, Any]]:
    """
    Get CrowdStrike prevention policies data using the 2-step process
    
    Args:
        logger: Logger instance
        api_key: CrowdStrike API key in format 'client_id:client_secret'
        base_url: CrowdStrike base URL (optional, defaults to US Commercial)
        
    Returns:
        List of prevention policy events for Splunk
    """
    if PreventionPolicy is None:
        logger.error("FalconPy SDK not available. Please install falconpy package.")
        return [{
            "timestamp": time.time(),
            "status": "critical",
            "message": "FalconPy SDK not available - cannot retrieve prevention policies",
            "error_details": {"error": "Missing falconpy dependency"}
        }]
    
    # Use default base URL if not provided
    if not base_url:
        base_url = const.us_commercial_base
        
    logger.info(f"Retrieving CrowdStrike prevention policies from: {base_url}")
    
    # Parse API key (assuming format: client_id:client_secret)
    if ':' not in api_key:
        logger.error("Invalid API key format. Expected 'client_id:client_secret'")
        return [{
            "timestamp": time.time(),
            "status": "critical",
            "message": "Invalid API key format",
            "error_details": {"error": "Expected 'client_id:client_secret' format"}
        }]
    
    client_id, client_secret = api_key.split(':', 1)
    
    try:
        # Initialize the Prevention Policy API client
        falcon = PreventionPolicy(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        
        logger.info("Step 1: Querying all prevention policy IDs")
        
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
                logger.error(f"Failed to query policy IDs: {result}")
                return [{
                    "timestamp": time.time(),
                    "status": "critical", 
                    "message": f"Failed to query prevention policy IDs: HTTP {result.get('status_code')}",
                    "api_endpoint": "query_combined_policies",
                    "error_details": {"status_code": result.get("status_code"), "response": result}
                }]
            
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
        
        if not policy_ids:
            logger.warning("No prevention policies found")
            return [{
                "timestamp": time.time(),
                "status": "warning",
                "message": "No prevention policies found in CrowdStrike",
                "policy_count": 0
            }]
        
        logger.info("Step 2: Fetching full policy details with settings")
        
        # Step 2: Fetch full settings for those policies (in chunks of 100)
        all_policies = []
        chunk_count = 0
        
        for i in range(0, len(policy_ids), 100):
            chunk_count += 1
            chunk = policy_ids[i:i + 100]
            logger.debug(f"Fetching policy details chunk {chunk_count} ({len(chunk)} policies)")
            
            detail_result = falcon.get_policies(ids=chunk)
            
            if detail_result.get("status_code") not in [200, 201]:
                logger.error(f"Failed to get policy details for chunk {chunk_count}: {detail_result}")
                # Continue with other chunks but record the error
                all_policies.append({
                    "timestamp": time.time(),
                    "status": "critical",
                    "message": f"Failed to retrieve policy details for chunk {chunk_count}",
                    "api_endpoint": "get_policies", 
                    "error_details": {"status_code": detail_result.get("status_code"), "chunk": chunk_count}
                })
                continue
            
            if "resources" in detail_result:
                policies_in_chunk = detail_result["resources"]
                all_policies.extend(policies_in_chunk)
                logger.debug(f"Retrieved {len(policies_in_chunk)} policy details in chunk {chunk_count}")
        
        logger.info(f"Step 2 completed: Retrieved details for {len([p for p in all_policies if 'name' in p])} policies")
        
        # Convert policies to Splunk events
        policy_events = []
        
        for policy in all_policies:
            # Skip error events (they don't have 'name' field)
            if 'name' not in policy:
                policy_events.append(policy)  # These are already formatted as error events
                continue
                
            # Create base policy event
            policy_event = {
                "timestamp": time.time(),
                "status": "healthy",
                "message": f"Prevention policy retrieved: {policy['name']}",
                "policy_id": policy.get("id"),
                "policy_name": policy.get("name"),
                "policy_description": policy.get("description", ""),
                "policy_platform": policy.get("platform_name", ""),
                "policy_enabled": policy.get("enabled", False),
                "policy_created_timestamp": policy.get("created_timestamp"),
                "policy_modified_timestamp": policy.get("modified_timestamp"),
                "policy_created_by": policy.get("created_by"),
                "policy_modified_by": policy.get("modified_by"),
                "settings_count": len(policy.get("settings", []))
            }
            
            # Add settings as structured data
            settings_data = []
            for setting in policy.get("settings", []):
                setting_info = {
                    "name": setting.get("name"),
                    "value": setting.get("value"),
                    "type": setting.get("type")
                }
                settings_data.append(setting_info)
            
            policy_event["policy_settings"] = settings_data
            
            # Add prevention settings summary for easier searching
            prevention_settings = {}
            for setting in policy.get("settings", []):
                setting_name = setting.get("name", "")
                setting_value = setting.get("value", "")
                if setting_name:
                    prevention_settings[setting_name] = setting_value
            
            policy_event["prevention_settings"] = prevention_settings
            
            policy_events.append(policy_event)
        
        # Add summary event
        successful_policies = len([e for e in policy_events if e.get("status") == "healthy"])
        error_count = len([e for e in policy_events if e.get("status") == "critical"])
        
        summary_event = {
            "timestamp": time.time(),
            "status": "healthy" if error_count == 0 else "warning",
            "message": f"Prevention policy collection completed: {successful_policies} policies retrieved, {error_count} errors",
            "summary": True,
            "total_policies": len(policy_ids),
            "successful_retrievals": successful_policies,
            "error_count": error_count,
            "collection_time": datetime.utcnow().isoformat()
        }
        
        policy_events.insert(0, summary_event)  # Add summary as first event
        
        logger.info(f"Prevention policy data collection completed: {len(policy_events)} events generated")
        return policy_events
        
    except Exception as e:
        logger.error(f"Exception while retrieving prevention policies: {e}")
        return [{
            "timestamp": time.time(),
            "status": "critical",
            "message": f"Exception while retrieving prevention policies: {str(e)}",
            "error_details": {"exception": str(e)}
        }]


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
        logger = logger_for_input(normalized_input_name)
        
        try:
            session_key = inputs.metadata["session_key"]
            
            # Configure logging
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="ta_crowdstrike_xdr_settings",
            )
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)
            
            # Get account configuration
            account_name = input_item.get("account")
            if not account_name:
                logger.error("No account specified in input configuration")
                continue
                
            api_key = get_account_api_key(session_key, account_name)
            if not api_key:
                logger.error(f"No API key found for account: {account_name}")
                continue
                
            base_url = get_base_url_from_settings(session_key, account_name)
            logger.info(f"Using CrowdStrike base URL: {base_url}")
            
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
            policy_events = get_prevention_policies_data(
                logger=logger,
                api_key=api_key,
                base_url=base_url
            )
            
            if not policy_events:
                logger.warning("No prevention policy events generated")
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
            
            # Add TA data to each event
            for event in policy_events:
                event['ta_data'] = ta_data
            
            # Send events to Splunk
            sourcetype = "crowdstrike:prevention_policies:json"
            index = input_item.get("index", "default")
            
            try:
                logger.info(f"Sending {len(policy_events)} prevention policy events to Splunk")
                
                # Send events individually to maintain proper event boundaries
                for event in policy_events:
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(event, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                        )
                    )
                
                logger.info(f"Successfully sent {len(policy_events)} prevention policy events to Splunk")
                
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
                # Create error event
                error_event = {
                    "timestamp": time.time(),
                    "status": "critical",
                    "message": f"Failed to send prevention policy events to Splunk: {str(send_error)}",
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
            logger.error(f"Exception in prevention policy collection for {normalized_input_name}: {e}")
            log.log_exception(
                logger, 
                e, 
                "prevention_policy_error", 
                msg_before=f"Exception raised while collecting prevention policies for {normalized_input_name}: "
            )
            
            # Try to send exception as event
            try:
                error_event = {
                    "timestamp": time.time(),
                    "status": "critical",
                    "message": f"Prevention policy collection exception: {str(e)}",
                    "error_details": {"exception": str(e), "input_name": normalized_input_name}
                }
                
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(error_event, ensure_ascii=False, default=str),
                        index=input_item.get("index", "default"),
                        sourcetype="crowdstrike:prevention_policies",
                    )
                )
            except Exception:
                # If we can't even send the error event, just log it
                logger.error("Failed to send exception event to Splunk")
