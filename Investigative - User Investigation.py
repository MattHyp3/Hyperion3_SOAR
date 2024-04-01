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

    format_auth_yes = phantom.get_format_data(name="format_auth_yes")
    format_auth_host_results = phantom.get_format_data(name="format_auth_host_results")

    parameters = []

    parameters.append({
        "input_1": format_auth_yes,
        "input_2": format_auth_host_results,
        "input_3": None,
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

    phantom.act("run query", parameters=parameters, name="search_user_auth_hosts", assets=["splunkes"], callback=format_auth_host_results)

    return


@phantom.playbook_block()
def format_auth_host_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_auth_host_results() called")

    template = """How many hosts has the user logged onto in the time period?\n**{0}**\n\nWhat were the unique hosts involved?\n**{1}**\n {2}\n {3}\n"""

    # parameter list for template variable replacement
    parameters = [
        "search_user_auth_hosts:action_result.data.*.host_count",
        "search_user_auth_hosts:action_result.data.*.host_list",
        "search_user_auth_hosts:action_result.data.*.content.host_list",
        "search_user_auth_hosts:action_result.data.*.content.host_list[]"
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

    add_comment_add_note_2(container=container)

    return


@phantom.playbook_block()
def add_comment_add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_add_note_2() called")

    format_auth_summary = phantom.get_format_data(name="format_auth_summary")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_auth_summary)
    phantom.add_note(container=container, content=format_auth_summary, note_format="markdown", note_type="general", title="Auth Summary")

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