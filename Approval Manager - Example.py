"""
This playbook will automatically run as a sub playbook when correlation search &quot;Request Monitor&quot; triggers based on an ES notable status change to &quot;Remediation Requested&quot;. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_approval_message' block
    format_approval_message(container=container)

    return

@phantom.playbook_block()
def approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("approval() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Asset Owner"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_approval_message:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Approve Splunk ES notable for endpoint agent automation?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=720, name="approval", parameters=parameters, response_types=response_types, callback=approved)

    return


@phantom.playbook_block()
def approved(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("approved() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["approval:action_result.summary.responses.0", "==", "Yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_notables_approved(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    get_notables_denied(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def update_es_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_es_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Automation Request was denied.""",
        parameters=[
            "container:id",
            "container:url"
        ])

    id_value = container.get("id", None)
    url_value = container.get("url", None)
    get_notables_denied__as_list = phantom.get_format_data(name="get_notables_denied__as_list")

    parameters = []

    # build parameters list for 'update_es_notable' call
    for get_notables_denied__item in get_notables_denied__as_list:
        if get_notables_denied__item is not None:
            parameters.append({
                "status": "remediation denied",
                "comment": comment_formatted_string,
                "event_ids": get_notables_denied__item,
                "wait_for_confirmation": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_es_notable", assets=["splunkes"], callback=join_playbook_container_resolution_1)

    return


@phantom.playbook_block()
def join_playbook_container_resolution_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_playbook_container_resolution_1() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_playbook_container_resolution_1_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_playbook_container_resolution_1_called", value="playbook_container_resolution_1")

    # call connected block "playbook_container_resolution_1"
    playbook_container_resolution_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def playbook_container_resolution_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_container_resolution_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "soar-h3/Container Resolution", returns the playbook_run_id
    playbook_run_id = phantom.playbook("soar-h3/Container Resolution", container=container)

    return


@phantom.playbook_block()
def update_es_notable_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_es_notable_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""Automation Request was approved.\nConduct automation actions as required.""",
        parameters=[
            "container:id",
            "container:url"
        ])

    id_value = container.get("id", None)
    url_value = container.get("url", None)
    get_notables_approved__as_list = phantom.get_format_data(name="get_notables_approved__as_list")

    parameters = []

    # build parameters list for 'update_es_notable_1' call
    for get_notables_approved__item in get_notables_approved__as_list:
        if get_notables_approved__item is not None:
            parameters.append({
                "status": "automation approved",
                "comment": comment_formatted_string,
                "event_ids": get_notables_approved__item,
                "wait_for_confirmation": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_es_notable_1", assets=["splunkes"], callback=join_playbook_container_resolution_1)

    return


@phantom.playbook_block()
def format_approval_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_approval_message() called")

    template = """{1} has requested approval for automation on the following hosts\n\n{0}\n\n{1}'s comment\n{2}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.Endpoint",
        "artifact:*.cef.owner",
        "artifact:*.cef.Comment"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_approval_message", separator=",", drop_none=True)

    approval(container=container)

    return


@phantom.playbook_block()
def get_notables_approved(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_notables_approved() called")

    template = """%%\n{0}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.notable_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_notables_approved", drop_none=True)

    update_es_notable_1(container=container)

    return


@phantom.playbook_block()
def get_notables_denied(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_notables_denied() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.notable_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="get_notables_denied", drop_none=True)

    update_es_notable(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return