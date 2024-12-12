"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_urls_as_array' block
    list_urls_as_array(container=container)

    return

@phantom.playbook_block()
def list_urls_as_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_urls_as_array() called")

    template = """%%\n{0}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="list_urls_as_array", drop_none=True)

    refang_url(container=container)

    return


@phantom.playbook_block()
def refang_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refang_url() called")

    list_urls_as_array__as_list = phantom.get_format_data(name="list_urls_as_array__as_list")

    refang_url__refanged_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    def refang(defanged_urls):
        refanged_urls = []
        
   # interate over the list of urls
        for url in defanged_urls:
            if url == None or len(url) == 0:
                # skip empty urls
                continue
                
            phantom.debug("Before refang: {}".format(url))
            
            url = url.replace("hxxp", "http")
            url = url.replace("[.]", ".")
            url = url.replace("[at]", "@")
            url = url.replace("\\", "")

            phantom.debug("After refang: {}".format(url))
            
            refanged_urls.append(url)
            
        return refanged_urls
            

    phantom.debug(list_urls_as_array__as_list)
    refang_url__refanged_url = refang(list_urls_as_array__as_list)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="refang_url:refanged_url", value=json.dumps(refang_url__refanged_url))

    fanged_urls(container=container)

    return


@phantom.playbook_block()
def fanged_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fanged_urls() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "refang_url:custom_function:refanged_urls"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="fanged_urls", drop_none=True)

    detonate_url_1(container=container)

    return


@phantom.playbook_block()
def format_report_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_report_url() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """SOAR detonated URL(s) using AnyRun.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n%%\n| `{0}` |  | {2} | https://www.virustotal.com/gui/url/{3} | VirusTotal v3 |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.parameter.url",
        "normalize_score_url:custom_function:score",
        "normalize_score_url:custom_function:categories",
        "filtered-data:url_result_filter:condition_1:url_reputation:action_result.data.*.id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_url", drop_none=True)

    update_event_2(container=container)

    return


@phantom.playbook_block()
def update_event_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.event_id","artifact:*.id"])
    format_report_url = phantom.get_format_data(name="format_report_url")

    parameters = []

    # build parameters list for 'update_event_2' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "comment": format_report_url,
                "event_ids": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_event_2", assets=["splunkes"], callback=add_note_1)

    return


@phantom.playbook_block()
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_1() called")

    format_report_url = phantom.get_format_data(name="format_report_url")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_report_url, note_format="markdown", note_type="general", title="Virus Total Scan results")

    return


@phantom.playbook_block()
def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("detonate_url_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    fanged_urls__as_list = phantom.get_format_data(name="fanged_urls__as_list")

    parameters = []

    # build parameters list for 'detonate_url_1' call
    for fanged_urls__item in fanged_urls__as_list:
        if fanged_urls__item is not None:
            parameters.append({
                "os": "Windows10x64_complete",
                "obj_type": "url",
                "env_locale": "en-US",
                "opt_timeout": 60,
                "obj_ext_browser": "Google Chrome",
                "opt_network_geo": "fastest",
                "opt_privacy_type": "bylink",
                "obj_ext_extension": True,
                "obj_ext_startfolder": "temp",
                "opt_network_connect": True,
                "opt_automated_interactivity": True,
                "opt_network_residential_proxy_geo": "fastest",
                "obj_url": fanged_urls__item,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="detonate_url_1", assets=["anyrun"], callback=format_report_url)

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