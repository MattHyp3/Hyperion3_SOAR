"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'mark_evidence_artifact' block
    mark_evidence_artifact(container=container)

    return

@phantom.playbook_block()
def mark_evidence_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("mark_evidence_artifact() called")

    id_value = container.get("id", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'mark_evidence_artifact' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "container": id_value,
            "content_type": "event_id",
            "input_object": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_evidence_artifact", callback=asset_get_splunk)

    return


@phantom.playbook_block()
def asset_get_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_get_splunk() called")

    parameters = []

    parameters.append({
        "asset": "splunk",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="asset_get_splunk", callback=asset_get_splunk_callback)

    return


@phantom.playbook_block()
def asset_get_splunk_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_get_splunk_callback() called")

    
    format_es_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_es_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_event_name(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def format_es_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_es_url() called")

    ################################################################################
    # Format a URL for the link back to the Notable ID. Change the port number as 
    # needed.
    ################################################################################

    template = """https://splunkes.com/:8000/en-US/app/SplunkEnterpriseSecuritySuite/incident_review?earliest={1}&latest=now&search=event_id%3D{2}"""

    # parameter list for template variable replacement
    parameters = [
        "asset_get_splunk:custom_function_result.data.configuration.device",
        "artifact:*.cef.info_min_time",
        "artifact:*.cef.event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_url", scope="all")

    pin_es_url(container=container)

    return


@phantom.playbook_block()
def pin_es_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_es_url() called")

    ################################################################################
    # Pin the Enterprise Security URL
    ################################################################################

    format_es_url = phantom.get_format_data(name="format_es_url")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_es_url, message="Enterprise Security URL", name="es_url", pin_style="grey", pin_type="card")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def format_es_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_es_note() called")

    ################################################################################
    # Format a note with the current event information.
    ################################################################################

    template = """SOAR event created: {0}\nComplete details can be found here: {1}/analyst/timeline\n\nClosing Notable with confirmed receipt"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_es_note", scope="all")

    update_notable(container=container)

    return


@phantom.playbook_block()
def update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Update the notable event  in Enterprise Security with a link back to this container
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"], scope="all")
    format_es_note = phantom.get_format_data(name="format_es_note")

    parameters = []

    # build parameters list for 'update_notable' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "status": "closed",
                "comment": format_es_note,
                "event_ids": container_artifact_item[0],
                "wait_for_confirmation": True,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_notable", assets=["splunkes"])

    return


@phantom.playbook_block()
def format_event_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_event_name() called")

    ################################################################################
    # Format the event name as 'Source: Risk Object'
    ################################################################################

    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.source"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_event_name", scope="all", drop_none=True)

    container_update_info(container=container)

    return


@phantom.playbook_block()
def container_update_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("container_update_info() called")

    id_value = container.get("id", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.urgency","artifact:*.cef.source","artifact:*.id"], scope="all")
    format_event_name = phantom.get_format_data(name="format_event_name")

    parameters = []

    # build parameters list for 'container_update_info' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "name": format_event_name,
            "tags": None,
            "label": None,
            "owner": None,
            "status": None,
            "severity": container_artifact_item[0],
            "input_json": None,
            "description": container_artifact_item[1],
            "sensitivity": None,
            "container_input": id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_info", callback=artifact_update_severity)

    return


@phantom.playbook_block()
def artifact_update_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_update_severity() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.id","artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'artifact_update_severity' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "name": None,
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": container_artifact_item[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_severity")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return