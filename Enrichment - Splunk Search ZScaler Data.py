"""
This playbook gathers all of the events associated with the Risk Notable and imports them as artifacts. It also generates a custom markdown formatted note.\t
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

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="get_splunk_asset_details", callback=get_splunk_asset_details_callback)

    return


@phantom.playbook_block()
def get_splunk_asset_details_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_splunk_asset_details_callback() called")

    
    format_risk_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    format_email_sender_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def format_risk_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_risk_query() called")

    ################################################################################
    # Formats a query to reach back into the risk index to pull out all the detections 
    # that led up to the notable triggering. The time tokens contain the earliest 
    # and latest times found in info_min_time and info_max_time
    ################################################################################

    template = """(index=zscaler sourcetype=zscalernss-web url IN({0}))\nOR \n(index IN (gateway, mcafee) sourcetype=mcafee:wg:kv url IN({0}))\nearliest=\"-30d\" latest=\"now\" \n| eval destip=coalesce(serverip, destip)\n| eval srcip=if(match(sourcetype, \"zscalernss-web\"), if(isnull(clientpublicIP) OR match(ClientIP, clientpublicIP), ClientIP, ClientIP + \" [NAT=\" + clientpublicIP + \"]\"), srcip)\n| eval user=if(match(index, \"gateway\") AND match(user, \"unknown\"), mvindex(split(host, \".\"), 0), user)\n| eval content_type=coalesce(mt, contenttype)\n| eval http_method=coalesce(requestmethod, http_method, mtd)\n| eval user_agent=coalesce(http_user_agent, useragent, ua)\n| eval bytes_to_server=coalesce(bytes_to_server, requestsize, mvindex(split(bytes, \"/\"), 0))\n| eval bytes_to_client=coalesce(bytes_to_client, responsesize, mvindex(split(bytes, \"/\"), 3))\n| eval block_id=if(match(status, \"/\"), mvindex(split(status, \"/\"), -1), null())\n| eval status=if(match(status, \"/\"), mvindex(split(status, \"/\"), 0), status)\n| eval action=coalesce(lower(action), action_fm_block_id)\n| eval domain=coalesce(dhost, hostname)\n| eval referrer=coalesce(refererURL, referer)\n| table _time user srcip destip threatname domain url referrer http_method content_type status action user_agent bytes_to_server bytes_to_client sourcetype source"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.artifact_domain",
        "artifact:*.cef.info_min_time",
        "artifact:*.cef.info_max_time"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_risk_query", scope="all", drop_none=True)

    run_query(container=container)

    return


@phantom.playbook_block()
def run_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Reaches back into splunk to search for any hits where the detected URL was accessed 
    # by users
    ################################################################################

    format_risk_query = phantom.get_format_data(name="format_risk_query")

    parameters = []

    if format_risk_query is not None:
        parameters.append({
            "query": format_risk_query,
            "command": "search",
            "parse_only": True,
            "attach_result": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query", assets=["splunkes"], callback=results_decision)

    return


@phantom.playbook_block()
def create_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_artifacts() called")

    id_value = container.get("id", None)
    run_query_result_data = phantom.collect2(container=container, datapath=["run_query:action_result.data.*","run_query:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'create_artifacts' call
    for run_query_result_item in run_query_result_data:
        parameters.append({
            "name": "splunk_search_results",
            "tags": None,
            "label": "splunk notable events",
            "severity": None,
            "cef_field": "result_data",
            "cef_value": run_query_result_item[0],
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

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_artifacts", callback=zscaler_results_seen)

    return


@phantom.playbook_block()
def results_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("results_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_query:action_result.summary.total_events", ">", 0]
        ],
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        create_artifacts(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    zscaler_no_results(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def zscaler_results_seen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("zscaler_results_seen() called")

    template = """Splunk results found as below\n\n{{code}}\nurl: {0}\nuser: {1}\n_time: {2}\nsrcip: {3}\naction: {4}\ndestip: {5}\ndomain: {6}\nsource: {7}\nstatus: {8}\nreferrer: {9}\nsourcetype: {10}\nthreatname: {11}\nuser_agent: {12}\nhttp_method: {13}\ncontent_type: {14}\nbytes_to_client: {15}\nbytes_to_server: {16}\n{{code}}\n"""

    # parameter list for template variable replacement
    parameters = [
        "run_query:action_result.data.*.url",
        "run_query:action_result.data.*.user",
        "run_query:action_result.data.*._time",
        "run_query:action_result.data.*.srcip",
        "run_query:action_result.data.*.action",
        "run_query:action_result.data.*.destip",
        "run_query:action_result.data.*.domain",
        "run_query:action_result.data.*.source",
        "run_query:action_result.data*.status",
        "run_query:action_result.data.*.referrer",
        "run_query:action_result.data.*.sourcetype",
        "run_query:action_result.data.*.threatname",
        "run_query:action_result.data.*.user_agent",
        "run_query:action_result.data.*.http_method",
        "run_query:action_result.data.*.content_type",
        "run_query:action_result.data.*.bytes_to_client",
        "run_query:action_result.data.*.bytes_to_server"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="zscaler_results_seen")

    return


@phantom.playbook_block()
def zscaler_no_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("zscaler_no_results() called")

    template = """No results seen for URL {0} when searching  zscaler or gateway data in the last 24 hours."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:event.cef.url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="zscaler_no_results")

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    zscaler_no_results = phantom.get_format_data(name="zscaler_no_results")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=zscaler_no_results, note_format="markdown", note_type="general", title="Splunk search results")

    return


@phantom.playbook_block()
def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content="search results added to Jira ticket", note_format="markdown", note_type="general", title="Splunk search results")

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
            "parse_only": True,
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