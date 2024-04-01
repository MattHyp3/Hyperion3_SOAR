"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_query_user_auth' block
    format_query_user_auth(container=container)

    return

@phantom.playbook_block()
def search_user_auth(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_user_auth() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_query_user_auth = phantom.get_format_data(name="format_query_user_auth")

    parameters = []

    if format_query_user_auth is not None:
        parameters.append({
            "command": "| tstats",
            "search_mode": "fast",
            "query": format_query_user_auth,
            "display": "count",
            "start_time": 1534737603,
            "end_time": 1568916650,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_user_auth", assets=["splunkes"], callback=decide_user_auth)

    return


@phantom.playbook_block()
def format_query_user_auth(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_query_user_auth() called")

    template = """count from datamodel=Authentication where Authentication.user=\"{0}\"\n| eval result = if(count > 0, \"1\", \"0\")\n| fields result"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.suser"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_query_user_auth")

    search_user_auth(container=container)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    search_makeresults_hosts_result_data = phantom.collect2(container=container, datapath=["search_makeresults_hosts:action_result.data.*.hosts","search_makeresults_hosts:action_result.parameter.context.artifact_id"], action_results=results)
    format_host_results = phantom.get_format_data(name="format_host_results")
    format_auth_host_results = phantom.get_format_data(name="format_auth_host_results")

    search_makeresults_hosts_result_item_0 = [item[0] for item in search_makeresults_hosts_result_data]

    parameters = []

    parameters.append({
        "input_1": format_host_results,
        "input_2": search_makeresults_hosts_result_item_0,
        "input_3": format_auth_host_results,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def decide_user_auth(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decide_user_auth() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["search_user_auth:action_result.data.*.result", ">", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_auth_yes(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_auth_no(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_auth_yes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_auth_yes() called")

    template = """Has user {0} has been active in the environment in the last seven days?\n**Yes**\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.suser"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_auth_yes")

    format_query_auth_hosts(container=container)

    return


@phantom.playbook_block()
def format_auth_no(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_auth_no() called")

    template = """Has user {0} has been active in the environment in the last seven days?\n**No**"""

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

    phantom.format(container=container, template=template, parameters=parameters, name="format_auth_no")

    join_format_auth_summary(container=container)

    return


@phantom.playbook_block()
def format_query_auth_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_query_auth_hosts() called")

    template = """dc(host) as host_count values(host) as host_list from datamodel=Authentication where Authentication.user=\"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.suser"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_query_auth_hosts")

    search_user_auth_hosts(container=container)

    return


@phantom.playbook_block()
def search_user_auth_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_user_auth_hosts() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_query_auth_hosts = phantom.get_format_data(name="format_query_auth_hosts")

    parameters = []

    if format_query_auth_hosts is not None:
        parameters.append({
            "command": "| tstats",
            "search_mode": "fast",
            "query": format_query_auth_hosts,
            "start_time": 1534737603,
            "end_time": 1568916650,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_user_auth_hosts", assets=["splunkes"], callback=format_host_results)

    return


@phantom.playbook_block()
def format_auth_host_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_auth_host_results() called")

    template = """How many hosts has the user logged onto in the time period?\n**{0}**\n\nWhat were the unique hosts involved?\n**{1}**\n"""

    # parameter list for template variable replacement
    parameters = [
        "search_user_auth_hosts:action_result.data.*.host_count",
        "search_makeresults_hosts:action_result.data.*.hosts"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_auth_host_results", drop_none=True)

    join_format_auth_summary(container=container)

    return


@phantom.playbook_block()
def join_format_auth_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_format_auth_summary() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_format_auth_summary_called"):
        return

    if phantom.completed(action_names=["search_makeresults_hosts"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_format_auth_summary_called", value="format_auth_summary")

        # call connected block "format_auth_summary"
        format_auth_summary(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_auth_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_auth_summary() called")

    template = """{0}{1}\n \n{2}\n \n"""

    # parameter list for template variable replacement
    parameters = [
        "format_auth_yes:formatted_data",
        "format_auth_no:formatted_data",
        "format_auth_host_results:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_auth_summary")

    format_query_malware(container=container)

    return


@phantom.playbook_block()
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_2() called")

    format_total_summary = phantom.get_format_data(name="format_total_summary")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_total_summary, note_format="markdown", note_type="general", title="Auth Summary")

    return


@phantom.playbook_block()
def format_host_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_host_results() called")

    template = """| eval _raw = \"{0}\"\n| rex field=_raw max_match=0 \"'(?<host>[^']+)'\"\n| eval hosts = mvjoin(host,\",\")\n| fields hosts\n"""

    # parameter list for template variable replacement
    parameters = [
        "search_user_auth_hosts:action_result.data.*.host_list"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_host_results")

    search_makeresults_hosts(container=container)

    return


@phantom.playbook_block()
def search_makeresults_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_makeresults_hosts() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_host_results = phantom.get_format_data(name="format_host_results")

    parameters = []

    if format_host_results is not None:
        parameters.append({
            "command": "| makeresults",
            "search_mode": "smart",
            "query": format_host_results,
            "start_time": 1534737603,
            "end_time": 1568916650,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_makeresults_hosts", assets=["splunkes"], callback=format_auth_host_results)

    return


@phantom.playbook_block()
def search_host_malware(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_host_malware() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_query_malware = phantom.get_format_data(name="format_query_malware")

    parameters = []

    if format_query_malware is not None:
        parameters.append({
            "command": "search",
            "search_mode": "fast",
            "start_time": 1534737603,
            "end_time": 1568916650,
            "query": format_query_malware,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_host_malware", assets=["splunkes"], callback=decision_host_malware)

    return


@phantom.playbook_block()
def format_query_malware(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_query_malware() called")

    template = """count from datamodel=Malware where host IN ({0})\n| eval result = if(count > 0, \"1\", \"0\")\n| fields result"""

    # parameter list for template variable replacement
    parameters = [
        "search_makeresults_hosts:action_result.data.*.hosts"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_query_malware")

    search_host_malware(container=container)

    return


@phantom.playbook_block()
def decision_host_malware(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_host_malware() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["search_host_malware:action_result.data.*.result", ">", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_malware_yes(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_malware_no(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_malware_yes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_malware_yes() called")

    template = """Has Malware been detected on any of the hosts of interest ({0})?\n**Yes**\n\nStarting Incident Response\n"""

    # parameter list for template variable replacement
    parameters = [
        "search_makeresults_hosts:action_result.data.*.hosts"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_malware_yes")

    magic_incident_response(container=container)

    return


@phantom.playbook_block()
def format_malware_no(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_malware_no() called")

    template = """Has Malware been detected on any of the hosts of interest ({0})?\n**No**"""

    # parameter list for template variable replacement
    parameters = [
        "search_makeresults_hosts:action_result.data.*.hosts"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_malware_no")

    join_format_malware_summary(container=container)

    return


@phantom.playbook_block()
def magic_incident_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("magic_incident_response() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    join_format_malware_summary(container=container)

    return


@phantom.playbook_block()
def join_format_malware_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_format_malware_summary() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_format_malware_summary_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_format_malware_summary_called", value="format_malware_summary")

    # call connected block "format_malware_summary"
    format_malware_summary(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_malware_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_malware_summary() called")

    template = """{0}{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "format_malware_yes:formatted_data",
        "format_malware_no:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_malware_summary", drop_none=True)

    format_total_summary(container=container)

    return


@phantom.playbook_block()
def format_total_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_total_summary() called")

    template = """**Incident Summary**\n---\n \n{0} \n{1} \n"""

    # parameter list for template variable replacement
    parameters = [
        "format_auth_summary:formatted_data",
        "format_malware_summary:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_total_summary")

    add_note_2(container=container)

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