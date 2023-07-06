"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _aggregation_fields = require("../aggregation_fields");

const generalAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.id'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['rule.level']]
};
const awsAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.id'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['rule.level']]
};
const fimAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['syscheck.path'], _aggregation_fields.AggregationFields['syscheck.event']]
};
const gcpAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.id'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['rule.level']]
};
const officeAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.id'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['rule.level']]
};
const pciAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['rule.pci_dss'], _aggregation_fields.AggregationFields['rule.description']]
};
const gdprAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['rule.gdpr'], _aggregation_fields.AggregationFields['rule.description']]
};
const nistAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['rule.nist_800_53'], _aggregation_fields.AggregationFields['rule.level']]
};
const hipaaAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['rule.hipaa'], _aggregation_fields.AggregationFields['rule.level']]
};
const tscAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['rule.tsc'], _aggregation_fields.AggregationFields['rule.description']]
};
const virustotalAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.id'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['rule.level']]
};
const osqueryAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['data.osquery.name'], _aggregation_fields.AggregationFields['data.osquery.action'], _aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['data.osquery.pack'], _aggregation_fields.AggregationFields['data.osquery.calendarTime']]
};
const mitreAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.id'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['rule.level']]
};
const ciscatAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['data.cis.rule_title'], _aggregation_fields.AggregationFields['data.cis.group'], _aggregation_fields.AggregationFields['data.cis.result']]
};
const pmAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['data.title']]
};
const dockerAlertsSummary = {
  title: 'Events summary',
  aggs: [_aggregation_fields.AggregationFields['data.docker.Actor.Attributes.name'], _aggregation_fields.AggregationFields['data.docker.Action'], _aggregation_fields.AggregationFields['timestamp']]
};
const githubAlertsSummary = {
  title: 'Alerts summary',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['data.github.org'], _aggregation_fields.AggregationFields['rule.description']]
}; // 'Wazuh-App-Overview-OSCAP-Last-alerts'

const oscapLastAlerts = {
  title: 'Last alerts',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['data.oscap.check.title'], _aggregation_fields.AggregationFields['data.oscap.scan.profile.title']]
}; // 'Wazuh-App-Overview-Audit-Last-alerts'

const auditLastAlerts = {
  title: 'Last alerts',
  aggs: [_aggregation_fields.AggregationFields['agent.name'], _aggregation_fields.AggregationFields['rule.description'], _aggregation_fields.AggregationFields['data.audit.exe']]
};
var _default = {
  aws: [awsAlertsSummary],
  ciscat: [ciscatAlertsSummary],
  docker: [dockerAlertsSummary],
  fim: [fimAlertsSummary],
  gcp: [gcpAlertsSummary],
  gdpr: [gdprAlertsSummary],
  general: [generalAlertsSummary],
  github: [githubAlertsSummary],
  hipaa: [hipaaAlertsSummary],
  mitre: [mitreAlertsSummary],
  nist: [nistAlertsSummary],
  office: [officeAlertsSummary],
  oscap: [oscapLastAlerts],
  osquery: [osqueryAlertsSummary],
  pci: [pciAlertsSummary],
  pm: [pmAlertsSummary],
  tsc: [tscAlertsSummary],
  virustotal: [virustotalAlertsSummary],
  audit: [auditLastAlerts]
};
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbImdlbmVyYWxBbGVydHNTdW1tYXJ5IiwidGl0bGUiLCJhZ2dzIiwiQWdncmVnYXRpb25GaWVsZHMiLCJhd3NBbGVydHNTdW1tYXJ5IiwiZmltQWxlcnRzU3VtbWFyeSIsImdjcEFsZXJ0c1N1bW1hcnkiLCJvZmZpY2VBbGVydHNTdW1tYXJ5IiwicGNpQWxlcnRzU3VtbWFyeSIsImdkcHJBbGVydHNTdW1tYXJ5IiwibmlzdEFsZXJ0c1N1bW1hcnkiLCJoaXBhYUFsZXJ0c1N1bW1hcnkiLCJ0c2NBbGVydHNTdW1tYXJ5IiwidmlydXN0b3RhbEFsZXJ0c1N1bW1hcnkiLCJvc3F1ZXJ5QWxlcnRzU3VtbWFyeSIsIm1pdHJlQWxlcnRzU3VtbWFyeSIsImNpc2NhdEFsZXJ0c1N1bW1hcnkiLCJwbUFsZXJ0c1N1bW1hcnkiLCJkb2NrZXJBbGVydHNTdW1tYXJ5IiwiZ2l0aHViQWxlcnRzU3VtbWFyeSIsIm9zY2FwTGFzdEFsZXJ0cyIsImF1ZGl0TGFzdEFsZXJ0cyIsImF3cyIsImNpc2NhdCIsImRvY2tlciIsImZpbSIsImdjcCIsImdkcHIiLCJnZW5lcmFsIiwiZ2l0aHViIiwiaGlwYWEiLCJtaXRyZSIsIm5pc3QiLCJvZmZpY2UiLCJvc2NhcCIsIm9zcXVlcnkiLCJwY2kiLCJwbSIsInRzYyIsInZpcnVzdG90YWwiLCJhdWRpdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBLE1BQU1BLG9CQUFvQixHQUFHO0FBQzNCQyxFQUFBQSxLQUFLLEVBQUUsZ0JBRG9CO0FBRTNCQyxFQUFBQSxJQUFJLEVBQUUsQ0FDSkMsc0NBQWtCLFNBQWxCLENBREksRUFFSkEsc0NBQWtCLGtCQUFsQixDQUZJLEVBR0pBLHNDQUFrQixZQUFsQixDQUhJO0FBRnFCLENBQTdCO0FBU0EsTUFBTUMsZ0JBQWdCLEdBQUc7QUFDdkJILEVBQUFBLEtBQUssRUFBRSxnQkFEZ0I7QUFFdkJDLEVBQUFBLElBQUksRUFBRSxDQUNKQyxzQ0FBa0IsU0FB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QUFBLEtBQUssRUFBRSxDQUFDbkIsZUFBRDtBQW5CTSxDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQWdncmVnYXRpb25GaWVsZHMgfSBmcm9tICcuLi9hZ2dyZWdhdGlvbl9maWVsZHMnO1xuY29uc3QgZ2VuZXJhbEFsZXJ0c1N1bW1hcnkgPSB7XG4gIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICBhZ2dzOiBbXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuaWQnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5kZXNjcmlwdGlvbiddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmxldmVsJ10sXG4gIF1cbn1cblxuY29uc3QgYXdzQWxlcnRzU3VtbWFyeSA9IHtcbiAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gIGFnZ3M6IFtcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5pZCddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmRlc2NyaXB0aW9uJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUubGV2ZWwnXSxcbiAgXVxufVxuXG5jb25zdCBmaW1BbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydhZ2VudC5uYW1lJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3N5c2NoZWNrLnBhdGgnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snc3lzY2hlY2suZXZlbnQnXSxcbiAgXVxufVxuXG5jb25zdCBnY3BBbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmlkJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuZGVzY3JpcHRpb24nXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5sZXZlbCddLFxuICBdXG59XG5cbmNvbnN0IG9mZmljZUFsZXJ0c1N1bW1hcnkgPSB7XG4gIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICBhZ2dzOiBbXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuaWQnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5kZXNjcmlwdGlvbiddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmxldmVsJ10sXG4gIF1cbn1cblxuY29uc3QgcGNpQWxlcnRzU3VtbWFyeSA9IHtcbiAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gIGFnZ3M6IFtcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snYWdlbnQubmFtZSddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLnBjaV9kc3MnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5kZXNjcmlwdGlvbiddLFxuICBdXG59XG5cbmNvbnN0IGdkcHJBbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydhZ2VudC5uYW1lJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuZ2RwciddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmRlc2NyaXB0aW9uJ10sXG4gIF1cbn1cblxuY29uc3QgbmlzdEFsZXJ0c1N1bW1hcnkgPSB7XG4gIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICBhZ2dzOiBbXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ2FnZW50Lm5hbWUnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5uaXN0XzgwMF81MyddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmxldmVsJ10sXG4gIF1cbn1cblxuY29uc3QgaGlwYWFBbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydhZ2VudC5uYW1lJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuaGlwYWEnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5sZXZlbCddLFxuICBdXG59XG5cbmNvbnN0IHRzY0FsZXJ0c1N1bW1hcnkgPSB7XG4gIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICBhZ2dzOiBbXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ2FnZW50Lm5hbWUnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS50c2MnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5kZXNjcmlwdGlvbiddLFxuICBdXG59XG5cbmNvbnN0IHZpcnVzdG90YWxBbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmlkJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuZGVzY3JpcHRpb24nXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5sZXZlbCddLFxuICBdXG59XG5cbmNvbnN0IG9zcXVlcnlBbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydkYXRhLm9zcXVlcnkubmFtZSddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydkYXRhLm9zcXVlcnkuYWN0aW9uJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ2FnZW50Lm5hbWUnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5vc3F1ZXJ5LnBhY2snXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5vc3F1ZXJ5LmNhbGVuZGFyVGltZSddLFxuICBdXG59XG5cbmNvbnN0IG1pdHJlQWxlcnRzU3VtbWFyeSA9IHtcbiAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gIGFnZ3M6IFtcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1sncnVsZS5pZCddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmRlc2NyaXB0aW9uJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUubGV2ZWwnXSxcbiAgXVxufVxuY29uc3QgY2lzY2F0QWxlcnRzU3VtbWFyeSA9IHtcbiAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gIGFnZ3M6IFtcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5jaXMucnVsZV90aXRsZSddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydkYXRhLmNpcy5ncm91cCddLFxuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydkYXRhLmNpcy5yZXN1bHQnXSxcbiAgXVxufVxuY29uc3QgcG1BbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydydWxlLmRlc2NyaXB0aW9uJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ2RhdGEudGl0bGUnXSxcbiAgXVxufVxuXG5jb25zdCBkb2NrZXJBbGVydHNTdW1tYXJ5ID0ge1xuICB0aXRsZTogJ0V2ZW50cyBzdW1tYXJ5JyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydkYXRhLmRvY2tlci5BY3Rvci5BdHRyaWJ1dGVzLm5hbWUnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5kb2NrZXIuQWN0aW9uJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3RpbWVzdGFtcCddLFxuICBdXG59XG5cbmNvbnN0IGdpdGh1YkFsZXJ0c1N1bW1hcnkgPSB7XG4gIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICBhZ2dzOiBbXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ2FnZW50Lm5hbWUnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5naXRodWIub3JnJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuZGVzY3JpcHRpb24nXSxcbiAgXVxufVxuXG4vLyAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9TQ0FQLUxhc3QtYWxlcnRzJ1xuY29uc3Qgb3NjYXBMYXN0QWxlcnRzID0ge1xuICB0aXRsZTogJ0xhc3QgYWxlcnRzJyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydhZ2VudC5uYW1lJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ2RhdGEub3NjYXAuY2hlY2sudGl0bGUnXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5vc2NhcC5zY2FuLnByb2ZpbGUudGl0bGUnXSxcbiAgXVxufVxuXG4vLyAnV2F6dWgtQXBwLU92ZXJ2aWV3LUF1ZGl0LUxhc3QtYWxlcnRzJ1xuY29uc3QgYXVkaXRMYXN0QWxlcnRzID0ge1xuICB0aXRsZTogJ0xhc3QgYWxlcnRzJyxcbiAgYWdnczogW1xuICAgIEFnZ3JlZ2F0aW9uRmllbGRzWydhZ2VudC5uYW1lJ10sXG4gICAgQWdncmVnYXRpb25GaWVsZHNbJ3J1bGUuZGVzY3JpcHRpb24nXSxcbiAgICBBZ2dyZWdhdGlvbkZpZWxkc1snZGF0YS5hdWRpdC5leGUnXSxcbiAgXVxufVxuXG5leHBvcnQgZGVmYXVsdCB7XG4gIGF3czogW2F3c0FsZXJ0c1N1bW1hcnldLFxuICBjaXNjYXQ6IFtjaXNjYXRBbGVydHNTdW1tYXJ5XSxcbiAgZG9ja2VyOiBbZG9ja2VyQWxlcnRzU3VtbWFyeV0sXG4gIGZpbTogW2ZpbUFsZXJ0c1N1bW1hcnldLFxuICBnY3A6IFtnY3BBbGVydHNTdW1tYXJ5XSxcbiAgZ2RwcjogW2dkcHJBbGVydHNTdW1tYXJ5XSxcbiAgZ2VuZXJhbDogW2dlbmVyYWxBbGVydHNTdW1tYXJ5XSxcbiAgZ2l0aHViOiBbZ2l0aHViQWxlcnRzU3VtbWFyeV0sXG4gIGhpcGFhOiBbaGlwYWFBbGVydHNTdW1tYXJ5XSxcbiAgbWl0cmU6IFttaXRyZUFsZXJ0c1N1bW1hcnldLFxuICBuaXN0OiBbbmlzdEFsZXJ0c1N1bW1hcnldLFxuICBvZmZpY2U6IFtvZmZpY2VBbGVydHNTdW1tYXJ5XSxcbiAgb3NjYXA6IFtvc2NhcExhc3RBbGVydHNdLFxuICBvc3F1ZXJ5OiBbb3NxdWVyeUFsZXJ0c1N1bW1hcnldLFxuICBwY2k6IFtwY2lBbGVydHNTdW1tYXJ5XSxcbiAgcG06IFtwbUFsZXJ0c1N1bW1hcnldLFxuICB0c2M6IFt0c2NBbGVydHNTdW1tYXJ5XSxcbiAgdmlydXN0b3RhbDogW3ZpcnVzdG90YWxBbGVydHNTdW1tYXJ5XSxcbiAgYXVkaXQ6IFthdWRpdExhc3RBbGVydHNdLFxufVxuIl19