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

    template = """Carbon Black Cloud: {0} on {1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.watchlist_name",
        "artifact:*.cef.src_host"
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

    template = """h4. CARBON BLACK ALERT DETAILS\n \n*Notable name*: {3}\n*Alert description*: {14}\n*Alert time*: {1}\n\n*Notable Type*: Carbon Black Cloud Alert\n*Security Domain*: {4}\n*Alert Source*: {5}\n*SOAR Event ID*: {0}\n*ES Notable Event ID*: {6}\n \n----\nh4. DETAILS\n \n*Computer name*: {16}\n*User*: {9}\n*Process name*: {11}\n*Notification type*: {17}\n*Watchlist name*: {10}\n*Severity*: {7}\n\n{{code}}\n*IOC*: \n{15}\n{{code}}\n\n\n{{code}}\n*IOC Detail*: \n{13}\n{{code}}\n\n----\nh4. LINKS\n\n*SOAR Pivot URL*\nhttps://splunk.com/mission/{0}\n\n*ES Pivot URL*\n{2}\n \n*CB process analysis*: \n{12}\n\n*CB Alert dashboard*: \nhttps://defense-prodsyd.conferdeploy.net/alerts\n"""

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
        "artifact:*.cef.src_ip",
        "artifact:*.cef.suser",
        "artifact:*.cef.watchlist_name",
        "artifact:*.cef.process_path",
        "artifact:*.cef.sensor_pivot",
        "artifact:*.cef.ioc_attr",
        "artifact:*.cef.rule_description",
        "artifact:*.cef.ioc_value",
        "artifact:*.cef.src_host",
        "artifact:*.cef.notification_type",
        "artifact:*.cef.savedsearch_description"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_description")

    cbc_ticket(container=container)

    return


@phantom.playbook_block()
def cbc_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("cbc_ticket() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_summary = phantom.get_format_data(name="format_summary")
    format_description = phantom.get_format_data(name="format_description")

    parameters = []

    if format_summary is not None:
        parameters.append({
            "fields": "{\"customfield_10002\":{\"id\":\"11800\"}}",
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

    phantom.act("create ticket", parameters=parameters, name="cbc_ticket", assets=["csoc jira connector"], callback=artifact_create_1)

    return


@phantom.playbook_block()
def artifact_create_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create_1() called")

    id_value = container.get("id", None)
    cbc_ticket_result_data = phantom.collect2(container=container, datapath=["cbc_ticket:action_result.data.*.id","cbc_ticket:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'artifact_create_1' call
    for cbc_ticket_result_item in cbc_ticket_result_data:
        parameters.append({
            "name": "jira_ticket",
            "tags": None,
            "label": "Jira",
            "severity": None,
            "cef_field": "jira_ticket_id",
            "cef_value": cbc_ticket_result_item[0],
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

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_1", callback=format_3)

    return


@phantom.playbook_block()
def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_3() called")

    template = """Note for Jira ticket\n\nJira Ticket ID\n{0}\n\nJira Ticket Name\n{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "cbc_ticket:action_result.data.*.id",
        "cbc_ticket:action_result.data.*.name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    add_note_2(container=container)

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    format_note = phantom.get_format_data(name="format_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note, note_format="markdown", note_type="general", title="jira-ticket-id")

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