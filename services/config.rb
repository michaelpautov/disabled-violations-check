

coreo_aws_rule "s3-allusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write.html"
  display_name "All users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "High"
  objectives    ["bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AllUsers/i, /\bwrite\b/i]
  id_map "modifiers.bucket"
end

coreo_aws_rule "s3-allusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write-acp.html"
  display_name "All users can write the bucket ACP / ACL"
  description "Bucket has permissions (ACP / ACL) which let all users modify the permissions."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to edit permissions."
  level "High"
  objectives    [ "bucket_acl","bucket_acl"]
  audit_objects ["grants.grantee.uri", "grants.permission"]
  operators     ["=~", "=~"]
  raise_when    [/AllUsers/i, /\bwrite_acp\b/i]
  id_map "modifiers.bucket"
end


coreo_uni_util_variables "s3-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-s3" do
  service :s3
  action :run
  rules ${AUDIT_AWS_S3_ALERT_LIST}
#  regions ${AUDIT_AWS_S3_REGIONS}
  global_objective "buckets"
  global_modifier({:bucket => "buckets.name"})
end

coreo_uni_util_variables "s3-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.report'},
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.report' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-s3.number_violations'},

            ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-s3" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.9.7-beta14"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-s3.report}'
  function <<-EOH
 
function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log(`Error reading suppression.yaml file`);
      suppression = null;
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log(`Error reading table.yaml file`);
      table = null;
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));

  let alertListToJSON = "${AUDIT_AWS_EC2_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || null;
  json_input['table'] = table || null;
}


setTableAndSuppression();


function createConfig(argForConfig) {
    let JSON_INPUT = {
        "composite name": argForConfig.compositeName,
        "plan name": argForConfig.planName,
        "cloudObjects": argForConfig.cloudObjects,
        "userSchemes": argForConfig.table_input,
        "userSuppression": argForConfig.suppression_input,
        "alert list": argForConfig.alertListArray,
        "disabled": argForConfig.disabledArray
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const NO_OWNER_EMAIL = "mihail@cloudcoreo.com";
const OWNER_TAG = "${AUDIT_AWS_EC2_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;
let table_input = json_input['table'];
let suppression_input = json_input['suppression'];
let alertListArray = json_input['alert list'];
let cloudObjects = json_input['violations'];
let planName = json_input['plan name'];
let compositeName = json_input['composite name'];
let disabledArray = [];
const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, suppression_input, OWNER_TAG,
    table_input, alertListArray, disabledArray, ALLOW_EMPTY,
    SEND_ON, planName, compositeName
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
coreoExport('results', JSON.stringify(JSON_INPUT));
coreoExport('report', JSON.stringify(JSON_INPUT['cloudObjects']));

callback(emails);
  EOH
end



coreo_uni_util_variables "s3-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.s3-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.results'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-s3.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.report'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.table'}
            ])
end



coreo_uni_util_jsrunner "tags-rollup-s3" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
  function <<-EOH
const notifiers = json_input;
function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });
    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}
let textRollup = '';
setTextRollup();
callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-s3-to-tag-values" do
  action((("${AUDIT_AWS_S3_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-s3.return'
end


coreo_uni_util_notify "advise-s3-rollup" do
  action((("${AUDIT_AWS_S3_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_S3_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_S3_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_S3_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
cloud account name: PLAN::cloud_account_name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-s3.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_S3_ALERT_RECIPIENT}', :subject => 'CloudCoreo s3 rule results on PLAN::stack_name :: PLAN::name'
  })
end