"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_splunk_asset_details' block
    get_splunk_asset_details(container=container)

    return

@phantom.playbook_block()
def get_splunk_asset_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_splunk_asset_details() called")

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

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="get_splunk_asset_details", callback=format_email_sender_query)

    return


@phantom.playbook_block()
def format_email_sender_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_email_sender_query() called")

    template = """(index=msexchange sourcetype=\"MSExchange:*:MessageTracking\" sender=\"{0}\") OR\n(index=o365 sourcetype=ms:o365:reporting:messagetrace SenderAddress=\"{0}\") OR\n(index=mcafee sourcetype=mcafee:smtp Event=\"*Email Status*\" From=\"*{0}*\")\nearliest=-24h@h AND latest=now\n| rex field=_raw \"^[^\\<]+\\<(?<message_id_header>[^\\>]+)\\>\"\n| rex field=_raw \",\\s+to=(?<mcafee_rcpt>.*),\\s+virtual_host=\"\n| rex mode=sed field=mcafee_rcpt \"s/(\\<|\\>)//g\"\n| eval mcafee_rcpt=split(mcafee_rcpt, \", \")\n| eval mcafee_subj=if(match(sourcetype, \"mcafee:smtp\"), subject, null())\n| rex mode=sed field=mcafee_subj \"s/(^\\'|\\'$)//g\"\n| eval mcafee_sender=if(match(sourcetype, \"mcafee:smtp\"), From, null())\n| rex mode=sed field=mcafee_sender \"s/(^\\<|\\>$)//g\"\n| rex field=_raw \",\\s+attachment\\(s\\)=\\'(?<attachments>[^\\']+)\\'\"\n| eval attachments=split(attachments, \", \")\n| rex field=_raw \"number-attachment\\(s\\)=\\'(?<mcafee_num_attachments>[0-9]+)\\'\"\n| eval sender=lower(coalesce(SenderAddress, sender, mcafee_sender))\n| eval recipient=lower(coalesce(RecipientAddress, recipient, mcafee_rcpt))\n| eval subject=coalesce(mcafee_subj, Subject, subject)\n| eval event_id=upper(coalesce(Status, event_id, if(match(sourcetype, \"mcafee:smtp\"), \"RELAY\", null())))\n| eval num_attachments=coalesce(AttachCount, mcafee_num_attachments)\n| eval message_id=coalesce(MessageTraceId, message_id, msgid)\n| rename OriginalFromAddress AS envelope_from\n| eval indexSourcetype=index + \" [\" + sourcetype + \"]\"\n| search index=*\n| table _time host sender envelope_from recipient subject num_attachments attachments event_id indexSourcetype message_id message_id_header source_id inbox_autoforwarding | search \n| mvexpand recipient\n| search NOT recipient=*@parlaph.mail.onmicrosoft.com\n| eval event_id=coalesce(source_id.\":\".event_id, event_id)\n| fillnull value=\"\"\n| stats earliest(_time) as e, latest(_time) as l, values(event_id) as events, values(attachments) as attachments count by sender recipient subject message_id_header\n| sort e\n| eval firstevent=strftime(e, \"%d-%m-%y %H:%M:%S\"), lastevent=strftime(l, \"%d-%m-%y %H:%M:%S\"), events=mvjoin(events, \", \")\n| table firstevent, lastevent, sender, recipient, subject, attachments, events"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.senders"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_sender_query", drop_none=True)

    email_query(container=container)

    return


@phantom.playbook_block()
def email_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("email_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_email_sender_query = phantom.get_format_data(name="format_email_sender_query")

    parameters = []

    if format_email_sender_query is not None:
        parameters.append({
            "query": format_email_sender_query,
            "command": "search",
            "display": "",
            "parse_only": False,
            "attach_result": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="email_query", assets=["splunkes"], callback=decision_1)

    return


@phantom.playbook_block()
def results_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("results_found() called")

    template = """Results found for sender {0}\n\nLink to Dashboard\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.senders"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="results_found")

    add_note_1(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["email_query:action_result.summary.total_events", ">", 0]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        results_found(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    no_results(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_1() called")

    results_found = phantom.get_format_data(name="results_found")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=results_found, note_format="markdown", note_type="general", title="Splunk search results")

    update_event_1(container=container)

    return


@phantom.playbook_block()
def no_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_results() called")

    template = """No results seen when searching for sender {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.senders"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="no_results")

    add_note_6(container=container)

    return


@phantom.playbook_block()
def add_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_6() called")

    no_results = phantom.get_format_data(name="no_results")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=no_results, note_format="markdown", note_type="general", title="Splunk search results")

    update_event_2(container=container)

    return


@phantom.playbook_block()
def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    results_found = phantom.get_format_data(name="results_found")

    parameters = []

    # build parameters list for 'update_event_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "event_ids": container_artifact_item[0],
                "comment": results_found,
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

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["splunkes"])

    return


@phantom.playbook_block()
def update_event_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    no_results = phantom.get_format_data(name="no_results")

    parameters = []

    # build parameters list for 'update_event_2' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "event_ids": container_artifact_item[0],
                "comment": no_results,
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

    phantom.act("update event", parameters=parameters, name="update_event_2", assets=["splunkes"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_note = phantom.get_format_data(name="format_note")

    output = {
        "note_title": ["[Auto-Generated] Notable Event Summary"],
        "note_content": format_note,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
	
    # Error handling in case of playbook not being able to import data properly
    
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

    phantom.save_playbook_output_data(output=output)

    return