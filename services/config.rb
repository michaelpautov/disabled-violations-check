coreo_aws_rule "monitor-route-table-changes" do
  action :define
  service :user
  category "Audit"
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=123"
  display_name "Ensure Route Table configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Route Table configuration changes are not properly monitored and alerted"
  level "Warning"
  meta_cis_id "3.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "monitor-vpc-changes" do
  action :define
  service :user
  category "Audit"
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=126"
  display_name "Ensure VPC configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "VPC configuration changes are not properly monitored and alerted"
  level "Warning"
  meta_cis_id "3.14"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_uni_util_jsrunner "cis3-rollup" do
  action :run
  json_input '{}'
  function <<-'EOH'

const ruleMetaJSON = {
    'monitor-route-table-changes': COMPOSITE::coreo_aws_rule,
    'monitor-vpc-changes': COMPOSITE::coreo_aws_rule
};

callback(ruleMetaJSON);
  EOH
end