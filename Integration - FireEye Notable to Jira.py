"""
Creates Jira tickets for FireEye based events
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

    template = """{0} ({1})\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.rule_description",
        "artifact:*.cef.url"
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

    template = """h4. SPLUNK ALERT DETAILS\n\n*Alert name*: {0}\n*Event time*: {9}\n*Alert description*: \n{3}\n\n*Notable Type*: Splunk FireEye Alert\n*Security Domain*: {10}\n*Alert Source*: {12}\n*SOAR Event ID*: {8}\n*ES Notable Event ID*: {11}\n\n----\n\nh4. EVENT DETAILS\n*Earliest Received Time*: \n{13}\n*Latest Received Time*:\n{14}\n\n*Senders*: \n{{code}}\n{4}\n{{code}}\n*Recipients*: \n{{code}}\n{5}\n{{code}}\n*Subjects*:\n{{code}}\n{6}\n{{code}}\n*Suspicious URLs*: \n{{code}}\n{7}\n{{code}}\n----\nh4. LINKS\n\n*ES Pivot URL*\n{1}\n\n*SOAR Pivot URL*\nhttps://splunk.com/mission/{8}\n\n*Fireeye CMS*\nhttps://fire.com/login/login"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.rule_name",
        "artifact:*.cef.es_pivot",
        "artifact:*.cef.security_domain",
        "artifact:*.cef.savedsearch_description",
        "artifact:*.cef.senders",
        "artifact:*.cef.recipients",
        "artifact:*.cef.subjects",
        "artifact:*.cef.urls",
        "container:id",
        "container:create_time",
        "artifact:*.cef.security_domain",
        "artifact:*.cef.event_id",
        "artifact:*.cef.alert_source",
        "artifact:*.cef.earliestReceiveTime",
        "artifact:*.cef.latestReceiveTime"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_description", scope="all", drop_none=True)

    fireeye_ticket(container=container)

    return


@phantom.playbook_block()
def fireeye_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fireeye_ticket() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_summary = phantom.get_format_data(name="format_summary")
    format_description = phantom.get_format_data(name="format_description")

    parameters = []

    if format_summary is not None:
        parameters.append({
            "fields": "{\"customfield_10002\":{\"id\":\"10700\"}}",
            "summary": format_summary,
            "assignee": "Unassigned",
            "priority": "High",
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

    phantom.act("create ticket", parameters=parameters, name="fireeye_ticket", assets=["csoc jira connector"], callback=artifact_create_1)

    return


@phantom.playbook_block()
def artifact_create_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create_1() called")

    id_value = container.get("id", None)
    fireeye_ticket_result_data = phantom.collect2(container=container, datapath=["fireeye_ticket:action_result.data.*.id","fireeye_ticket:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'artifact_create_1' call
    for fireeye_ticket_result_item in fireeye_ticket_result_data:
        parameters.append({
            "name": "jira_ticket",
            "tags": None,
            "label": "Jira",
            "severity": None,
            "cef_field": "jira_ticket_id",
            "cef_value": fireeye_ticket_result_item[0],
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

    template = """Note for Jira ticket\n\nJira Ticket ID\n{0}\nJira Ticket Link\nhttps://splunk.com:8480/browse/{1}"""

    # parameter list for template variable replacement
    parameters = [
        "fireeye_ticket:action_result.data.*.id",
        "fireeye_ticket:action_result.data.*.name"
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

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["splunk"])

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