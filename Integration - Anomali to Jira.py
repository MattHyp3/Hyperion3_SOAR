"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_summary' block
    format_summary(container=container)

    return

@phantom.playbook_block()
def format_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_summary() called")

    template = """Anomali Match Indicator Hit - {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.indicator"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_summary")

    format_description(container=container)

    return


@phantom.playbook_block()
def format_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_description() called")

    template = """h4. ANOMALI MATCH ALERT DETAILS\n\n*Notable name*: {3}\n*Alert description*: {14}\n*Alert time*: {1}\n\n{18}\n\n*Notable Type*: Anomali Threat Match\n*Security Domain*:{4}\n*Alert Source*: {5}\n*SOAR Event ID*: {0}\n*ES Notable Event ID*: {6}\n \n----\nh4. EVENT DETAILS\n \n*Computer name*: {16}\n*IP address*: {8}\n*User*: {9}\n*Severity*: {7}\n*Event host*: {16}\n*Event destination*: {15}\n*Event action*: {12}\n*Event direction*: {19}\n\n----\nh4. INDICATOR DETAILS\n\n*Indicator*: {24}\n*Indicator type*: {20}\n*Indicator confidence*: {22}\n*Indicator severity*: {13}\n*Indicator age*: {23}\n*Indicator feed*: {21}\n*Indicator whois*: {25}\n\n----\nh4. LINKS\n\n*SOAR Pivot URL*\nhttps://splunk.com/mission/{0}\n\n*ES Pivot URL*\n{2}\n\n*Anomali Match*\nhttps://splunk.com:8080/\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:create_time",
        "artifact:*.cef.es_pivot",
        "artifact:*.cef.rule_name",
        "artifact:*.cef.security_domain",
        "artifact:*.cef.alert_source",
        "artifact:*.cef.event_id",
        "artifact:*.cef.severity",
        "artifact:*.cef.srcip",
        "artifact:*.cef.user",
        "artifact:*.cef.watchlist_name",
        "artifact:*.cef.process_path",
        "artifact:*.cef.action",
        "artifact:*.cef.severity",
        "artifact:*.cef.rule_description",
        "artifact:*.cef.dest",
        "artifact:*.cef.src_host",
        "artifact:*.cef.notification_type",
        "artifact:*.cef.savedsearch_description",
        "artifact:*.cef.direction",
        "artifact:*.cef.itype",
        "artifact:*.cef.source_feed",
        "artifact:*.cef.confidence",
        "artifact:*.cef.age",
        "artifact:*.cef.indicator",
        "artifact:*.cef.indicator_whois"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_description")

    anomali_match_ticket(container=container)

    return


@phantom.playbook_block()
def anomali_match_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("anomali_match_ticket() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_summary = phantom.get_format_data(name="format_summary")
    format_description = phantom.get_format_data(name="format_description")

    parameters = []

    if format_summary is not None:
        parameters.append({
            "fields": "{\"customfield_10002\":{\"id\":\"11500\"}}",
            "summary": format_summary,
            "assignee": "Unassigned",
            "priority": "Medium",
            "issue_type": "Alert",
            "description": format_description,
            "project_key": "ALERT",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ticket", parameters=parameters, name="anomali_match_ticket", assets=["csoc jira connector"], callback=artifact_create_1)

    return


@phantom.playbook_block()
def artifact_create_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create_1() called")

    id_value = container.get("id", None)
    anomali_match_ticket_result_data = phantom.collect2(container=container, datapath=["anomali_match_ticket:action_result.data.*.id","anomali_match_ticket:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'artifact_create_1' call
    for anomali_match_ticket_result_item in anomali_match_ticket_result_data:
        parameters.append({
            "name": "jira_ticket",
            "tags": None,
            "label": "Jira",
            "severity": None,
            "cef_field": "jira_ticket_id",
            "cef_value": anomali_match_ticket_result_item[0],
            "container": id_value,
            "input_json": None,
            "cef_data_type": None,
            "run_automation": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_1", callback=jira_ticket_note)

    return


@phantom.playbook_block()
def jira_ticket_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("jira_ticket_note() called")

    template = """Note for Jira ticket\n\nJira Ticket ID\n{0}\n\nJira Ticket Link\n\nhttps://splunk.com:8480/browse/{1}"""

    # parameter list for template variable replacement
    parameters = [
        "anomali_match_ticket:action_result.data.*.id",
        "anomali_match_ticket:action_result.data.*.name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="jira_ticket_note")

    add_note_2(container=container)

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    jira_ticket_note = phantom.get_format_data(name="jira_ticket_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=jira_ticket_note, note_format="markdown", note_type="general", title="Jira Ticket")

    update_event_1(container=container)

    return


@phantom.playbook_block()
def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    jira_ticket_note = phantom.get_format_data(name="jira_ticket_note")

    parameters = []

    # build parameters list for 'update_event_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "status": "closed",
                "comment": jira_ticket_note,
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

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["splunk"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.cef.action", "==", "blocked"],
            ["artifact:*.cef.suppressed_event", "==", "suppressed"]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        closure_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_status_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    anomali_match_ticket_result_data = phantom.collect2(container=container, datapath=["anomali_match_ticket:action_result.data.*.id","anomali_match_ticket:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'set_status_1' call
    for anomali_match_ticket_result_item in anomali_match_ticket_result_data:
        if anomali_match_ticket_result_item[0] is not None:
            parameters.append({
                "id": anomali_match_ticket_result_item[0],
                "status": "Done",
                "comment": "",
                "resolution": "Done",
                "update_fields": "{\"customfield_10002\":{\"id\":\"11500\"}}",
                "context": {'artifact_id': anomali_match_ticket_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("set status", parameters=parameters, name="set_status_1", assets=["csoc jira connector"])

    return


@phantom.playbook_block()
def closure_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("closure_note() called")

    ################################################################################
    # setting note for auto closure as an automated triage event
    ################################################################################

    template = """Ticket closed as auto triage as event was blocked and tagged as suppressed event."""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="closure_note")

    auto_close_note(container=container)

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    anomali_match_ticket_result_data = phantom.collect2(container=container, datapath=["anomali_match_ticket:action_result.data.*.id","anomali_match_ticket:action_result.parameter.context.artifact_id"], action_results=results)
    closure_note = phantom.get_format_data(name="closure_note")

    parameters = []

    # build parameters list for 'add_comment_1' call
    for anomali_match_ticket_result_item in anomali_match_ticket_result_data:
        if anomali_match_ticket_result_item[0] is not None and closure_note is not None:
            parameters.append({
                "id": anomali_match_ticket_result_item[0],
                "comment": closure_note,
                "internal": False,
                "context": {'artifact_id': anomali_match_ticket_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add comment", parameters=parameters, name="add_comment_1", assets=["csoc jira connector"], callback=set_status_1)

    return


@phantom.playbook_block()
def auto_close_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("auto_close_note() called")

    closure_note = phantom.get_format_data(name="closure_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=closure_note, note_format="markdown", note_type="general", title="Auto Close Note")

    add_comment_1(container=container)

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