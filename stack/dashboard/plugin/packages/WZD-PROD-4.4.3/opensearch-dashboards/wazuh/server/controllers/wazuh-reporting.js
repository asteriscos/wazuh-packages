"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhReportingCtrl = void 0;

var _path = _interopRequireDefault(require("path"));

var _fs = _interopRequireDefault(require("fs"));

var _wazuhModules = require("../../common/wazuh-modules");

var TimSort = _interopRequireWildcard(require("timsort"));

var _errorResponse = require("../lib/error-response");

var _processStateEquivalence = _interopRequireDefault(require("../lib/process-state-equivalence"));

var _csvKeyEquivalence = require("../../common/csv-key-equivalence");

var _agentConfiguration = require("../lib/reporting/agent-configuration");

var _extendedInformation = require("../lib/reporting/extended-information");

var _printer = require("../lib/reporting/printer");

var _logger = require("../lib/logger");

var _constants = require("../../common/constants");

var _filesystem = require("../lib/filesystem");

var _wz_agent_status = require("../../common/services/wz_agent_status");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class WazuhReportingCtrl {
  constructor() {
    _defineProperty(this, "createReportsModules", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsModules', `Report started`, 'info');
        const {
          array,
          agents,
          browserTimezone,
          searchBar,
          filters,
          time,
          tables,
          section,
          indexPatternTitle,
          apiId
        } = request.body;
        const {
          moduleID
        } = request.params;
        const {
          from,
          to
        } = time || {};
        let additionalTables = []; // Init

        const printer = new _printer.ReportPrinter();
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, context.wazuhEndpointParams.hashUsername));
        await this.renderHeader(context, printer, section, moduleID, agents, apiId);
        const [sanitizedFilters, agentsFilter] = filters ? this.sanitizeKibanaFilters(filters, searchBar) : [false, null];

        if (time && sanitizedFilters) {
          printer.addTimeRangeAndFilters(from, to, sanitizedFilters, browserTimezone);
        }

        if (time) {
          additionalTables = await (0, _extendedInformation.extendedInformation)(context, printer, section, moduleID, apiId, new Date(from).getTime(), new Date(to).getTime(), sanitizedFilters, agentsFilter, indexPatternTitle, agents);
        }

        printer.addVisualizations(array, agents, moduleID);

        if (tables) {
          printer.addTables([...tables, ...(additionalTables || [])]);
        } //add authorized agents


        if (agentsFilter !== null && agentsFilter !== void 0 && agentsFilter.agentsText) {
          printer.addAgentsFilters(agentsFilter.agentsText);
        }

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      body: {
        agents
      },
      params: {
        moduleID
      }
    }) => `wazuh-module-${agents ? `agents-${agents}` : 'overview'}-${moduleID}-${this.generateReportTimestamp()}.pdf`));

    _defineProperty(this, "createReportsGroups", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsGroups', `Report started`, 'info');
        const {
          components,
          apiId
        } = request.body;
        const {
          groupID
        } = request.params; // Init

        const printer = new _printer.ReportPrinter();
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, context.wazuhEndpointParams.hashUsername));
        let tables = [];
        const equivalences = {
          localfile: 'Local files',
          osquery: 'Osquery',
          command: 'Command',
          syscheck: 'Syscheck',
          'open-scap': 'OpenSCAP',
          'cis-cat': 'CIS-CAT',
          syscollector: 'Syscollector',
          rootcheck: 'Rootcheck',
          labels: 'Labels',
          sca: 'Security configuration assessment'
        };
        printer.addContent({
          text: `Group ${groupID} configuration`,
          style: 'h1'
        }); // Group configuration

        if (components['0']) {
          const {
            data: {
              data: configuration
            }
          } = await context.wazuh.api.client.asCurrentUser.request('GET', `/groups/${groupID}/configuration`, {}, {
            apiHostID: apiId
          });

          if (configuration.affected_items.length > 0 && Object.keys(configuration.affected_items[0].config).length) {
            printer.addContent({
              text: 'Configurations',
              style: {
                fontSize: 14,
                color: '#000'
              },
              margin: [0, 10, 0, 15]
            });
            const section = {
              labels: [],
              isGroupConfig: true
            };

            for (let config of configuration.affected_items) {
              let filterTitle = '';
              let index = 0;

              for (let filter of Object.keys(config.filters)) {
                filterTitle = filterTitle.concat(`${filter}: ${config.filters[filter]}`);

                if (index < Object.keys(config.filters).length - 1) {
                  filterTitle = filterTitle.concat(' | ');
                }

                index++;
              }

              printer.addContent({
                text: filterTitle,
                style: 'h4',
                margin: [0, 0, 0, 10]
              });
              let idx = 0;
              section.tabs = [];

              for (let _d of Object.keys(config.config)) {
                for (let c of _agentConfiguration.AgentConfiguration.configurations) {
                  for (let s of c.sections) {
                    section.opts = s.opts || {};

                    for (let cn of s.config || []) {
                      if (cn.configuration === _d) {
                        section.labels = s.labels || [[]];
                      }
                    }

                    for (let wo of s.wodle || []) {
                      if (wo.name === _d) {
                        section.labels = s.labels || [[]];
                      }
                    }
                  }
                }

                section.labels[0]['pack'] = 'Packs';
                section.labels[0]['content'] = 'Evaluations';
                section.labels[0]['7'] = 'Scan listening netwotk ports';
                section.tabs.push(equivalences[_d]);

                if (Array.isArray(config.config[_d])) {
                  /* LOG COLLECTOR */
                  if (_d === 'localfile') {
                    let groups = [];

                    config.config[_d].forEach(obj => {
                      if (!groups[obj.logformat]) {
                        groups[obj.logformat] = [];
                      }

                      groups[obj.logformat].push(obj);
                    });

                    Object.keys(groups).forEach(group => {
                      let saveidx = 0;
                      groups[group].forEach((x, i) => {
                        if (Object.keys(x).length > Object.keys(groups[group][saveidx]).length) {
                          saveidx = i;
                        }
                      });
                      const columns = Object.keys(groups[group][saveidx]);
                      const rows = groups[group].map(x => {
                        let row = [];
                        columns.forEach(key => {
                          row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
                            return x + '\n';
                          }) : JSON.stringify(x[key]));
                        });
                        return row;
                      });
                      columns.forEach((col, i) => {
                        columns[i] = col[0].toUpperCase() + col.slice(1);
                      });
                      tables.push({
                        title: 'Local files',
                        type: 'table',
                        columns,
                        rows
                      });
                    });
                  } else if (_d === 'labels') {
                    const obj = config.config[_d][0].label;
                    const columns = Object.keys(obj[0]);

                    if (!columns.includes('hidden')) {
                      columns.push('hidden');
                    }

                    const rows = obj.map(x => {
                      let row = [];
                      columns.forEach(key => {
                        row.push(x[key]);
                      });
                      return row;
                    });
                    columns.forEach((col, i) => {
                      columns[i] = col[0].toUpperCase() + col.slice(1);
                    });
                    tables.push({
                      title: 'Labels',
                      type: 'table',
                      columns,
                      rows
                    });
                  } else {
                    for (let _d2 of config.config[_d]) {
                      tables.push(...this.getConfigTables(_d2, section, idx));
                    }
                  }
                } else {
                  /*INTEGRITY MONITORING MONITORED DIRECTORIES */
                  if (config.config[_d].directories) {
                    const directories = config.config[_d].directories;
                    delete config.config[_d].directories;
                    tables.push(...this.getConfigTables(config.config[_d], section, idx));
                    let diffOpts = [];
                    Object.keys(section.opts).forEach(x => {
                      diffOpts.push(x);
                    });
                    const columns = ['', ...diffOpts.filter(x => x !== 'check_all' && x !== 'check_sum')];
                    let rows = [];
                    directories.forEach(x => {
                      let row = [];
                      row.push(x.path);
                      columns.forEach(y => {
                        if (y !== '') {
                          y = y !== 'check_whodata' ? y : 'whodata';
                          row.push(x[y] ? x[y] : 'no');
                        }
                      });
                      row.push(x.recursion_level);
                      rows.push(row);
                    });
                    columns.forEach((x, idx) => {
                      columns[idx] = section.opts[x];
                    });
                    columns.push('RL');
                    tables.push({
                      title: 'Monitored directories',
                      type: 'table',
                      columns,
                      rows
                    });
                  } else {
                    tables.push(...this.getConfigTables(config.config[_d], section, idx));
                  }
                }

                for (const table of tables) {
                  printer.addConfigTables([table]);
                }

                idx++;
                tables = [];
              }

              tables = [];
            }
          } else {
            printer.addContent({
              text: 'A configuration for this group has not yet been set up.',
              style: {
                fontSize: 12,
                color: '#000'
              },
              margin: [0, 10, 0, 15]
            });
          }
        } // Agents in group


        if (components['1']) {
          await this.renderHeader(context, printer, 'groupConfig', groupID, [], apiId);
        }

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:createReportsGroups', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      params: {
        groupID
      }
    }) => `wazuh-group-configuration-${groupID}-${this.generateReportTimestamp()}.pdf`));

    _defineProperty(this, "createReportsAgentsConfiguration", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsAgentsConfiguration', `Report started`, 'info');
        const {
          components,
          apiId
        } = request.body;
        const {
          agentID
        } = request.params;
        const printer = new _printer.ReportPrinter();
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, context.wazuhEndpointParams.hashUsername));
        let wmodulesResponse = {};
        let tables = [];

        try {
          wmodulesResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents/${agentID}/config/wmodules/wmodules`, {}, {
            apiHostID: apiId
          });
        } catch (error) {
          (0, _logger.log)('reporting:report', error.message || error, 'debug');
        }

        await this.renderHeader(context, printer, 'agentConfig', 'agentConfig', agentID, apiId);
        let idxComponent = 0;

        for (let config of _agentConfiguration.AgentConfiguration.configurations) {
          let titleOfSection = false;
          (0, _logger.log)('reporting:createReportsAgentsConfiguration', `Iterate over ${config.sections.length} configuration sections`, 'debug');

          for (let section of config.sections) {
            let titleOfSubsection = false;

            if (components[idxComponent] && (section.config || section.wodle)) {
              let idx = 0;
              const configs = (section.config || []).concat(section.wodle || []);
              (0, _logger.log)('reporting:createReportsAgentsConfiguration', `Iterate over ${configs.length} configuration blocks`, 'debug');

              for (let conf of configs) {
                let agentConfigResponse = {};

                try {
                  if (!conf['name']) {
                    agentConfigResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents/${agentID}/config/${conf.component}/${conf.configuration}`, {}, {
                      apiHostID: apiId
                    });
                  } else {
                    for (let wodle of wmodulesResponse.data.data['wmodules']) {
                      if (Object.keys(wodle)[0] === conf['name']) {
                        agentConfigResponse.data = {
                          data: wodle
                        };
                      }
                    }
                  }

                  const agentConfig = agentConfigResponse && agentConfigResponse.data && agentConfigResponse.data.data;

                  if (!titleOfSection) {
                    printer.addContent({
                      text: config.title,
                      style: 'h1',
                      margin: [0, 0, 0, 15]
                    });
                    titleOfSection = true;
                  }

                  if (!titleOfSubsection) {
                    printer.addContent({
                      text: section.subtitle,
                      style: 'h4'
                    });
                    printer.addContent({
                      text: section.desc,
                      style: {
                        fontSize: 12,
                        color: '#000'
                      },
                      margin: [0, 0, 0, 10]
                    });
                    titleOfSubsection = true;
                  }

                  if (agentConfig) {
                    for (let agentConfigKey of Object.keys(agentConfig)) {
                      if (Array.isArray(agentConfig[agentConfigKey])) {
                        /* LOG COLLECTOR */
                        if (conf.filterBy) {
                          let groups = [];
                          agentConfig[agentConfigKey].forEach(obj => {
                            if (!groups[obj.logformat]) {
                              groups[obj.logformat] = [];
                            }

                            groups[obj.logformat].push(obj);
                          });
                          Object.keys(groups).forEach(group => {
                            let saveidx = 0;
                            groups[group].forEach((x, i) => {
                              if (Object.keys(x).length > Object.keys(groups[group][saveidx]).length) {
                                saveidx = i;
                              }
                            });
                            const columns = Object.keys(groups[group][saveidx]);
                            const rows = groups[group].map(x => {
                              let row = [];
                              columns.forEach(key => {
                                row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
                                  return x + '\n';
                                }) : JSON.stringify(x[key]));
                              });
                              return row;
                            });
                            columns.forEach((col, i) => {
                              columns[i] = col[0].toUpperCase() + col.slice(1);
                            });
                            tables.push({
                              title: section.labels[0][group],
                              type: 'table',
                              columns,
                              rows
                            });
                          });
                        } else if (agentConfigKey.configuration !== 'socket') {
                          tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                        } else {
                          for (let _d2 of agentConfig[agentConfigKey]) {
                            tables.push(...this.getConfigTables(_d2, section, idx));
                          }
                        }
                      } else {
                        /*INTEGRITY MONITORING MONITORED DIRECTORIES */
                        if (conf.matrix) {
                          const {
                            directories,
                            diff,
                            synchronization,
                            file_limit,
                            ...rest
                          } = agentConfig[agentConfigKey];
                          tables.push(...this.getConfigTables(rest, section, idx), ...(diff && diff.disk_quota ? this.getConfigTables(diff.disk_quota, {
                            tabs: ['Disk quota']
                          }, 0) : []), ...(diff && diff.file_size ? this.getConfigTables(diff.file_size, {
                            tabs: ['File size']
                          }, 0) : []), ...(synchronization ? this.getConfigTables(synchronization, {
                            tabs: ['Synchronization']
                          }, 0) : []), ...(file_limit ? this.getConfigTables(file_limit, {
                            tabs: ['File limit']
                          }, 0) : []));
                          let diffOpts = [];
                          Object.keys(section.opts).forEach(x => {
                            diffOpts.push(x);
                          });
                          const columns = ['', ...diffOpts.filter(x => x !== 'check_all' && x !== 'check_sum')];
                          let rows = [];
                          directories.forEach(x => {
                            let row = [];
                            row.push(x.dir);
                            columns.forEach(y => {
                              if (y !== '') {
                                row.push(x.opts.indexOf(y) > -1 ? 'yes' : 'no');
                              }
                            });
                            row.push(x.recursion_level);
                            rows.push(row);
                          });
                          columns.forEach((x, idx) => {
                            columns[idx] = section.opts[x];
                          });
                          columns.push('RL');
                          tables.push({
                            title: 'Monitored directories',
                            type: 'table',
                            columns,
                            rows
                          });
                        } else {
                          tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                        }
                      }
                    }
                  } else {
                    // Print no configured module and link to the documentation
                    printer.addContent({
                      text: ['This module is not configured. Please take a look on how to configure it in ', {
                        text: `${section.subtitle.toLowerCase()} configuration.`,
                        link: section.docuLink,
                        style: {
                          fontSize: 12,
                          color: '#1a0dab'
                        }
                      }],
                      margin: [0, 0, 0, 20]
                    });
                  }
                } catch (error) {
                  (0, _logger.log)('reporting:report', error.message || error, 'debug');
                }

                idx++;
              }

              for (const table of tables) {
                printer.addConfigTables([table]);
              }
            }

            idxComponent++;
            tables = [];
          }
        }

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:createReportsAgentsConfiguration', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      params: {
        agentID
      }
    }) => `wazuh-agent-configuration-${agentID}-${this.generateReportTimestamp()}.pdf`));

    _defineProperty(this, "createReportsAgentsInventory", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsAgentsInventory', `Report started`, 'info');
        const {
          searchBar,
          filters,
          time,
          indexPatternTitle,
          apiId
        } = request.body;
        const {
          agentID
        } = request.params;
        const {
          from,
          to
        } = time || {}; // Init

        const printer = new _printer.ReportPrinter();
        const {
          hashUsername
        } = await context.wazuh.security.getCurrentUser(request, context);
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, hashUsername));
        (0, _logger.log)('reporting:createReportsAgentsInventory', `Syscollector report`, 'debug');
        const [sanitizedFilters, agentsFilter] = filters ? this.sanitizeKibanaFilters(filters, searchBar) : [false, null]; // Get the agent OS

        let agentOs = '';

        try {
          const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', '/agents', {
            params: {
              q: `id=${agentID}`
            }
          }, {
            apiHostID: apiId
          });
          agentOs = agentResponse.data.data.affected_items[0].os.platform;
        } catch (error) {
          (0, _logger.log)('reporting:createReportsAgentsInventory', error.message || error, 'debug');
        } // Add title


        printer.addContentWithNewLine({
          text: 'Inventory data report',
          style: 'h1'
        }); // Add table with the agent info

        await (0, _extendedInformation.buildAgentsTable)(context, printer, [agentID], apiId); // Get syscollector packages and processes

        const agentRequestsInventory = [{
          endpoint: `/syscollector/${agentID}/packages`,
          loggerMessage: `Fetching packages for agent ${agentID}`,
          table: {
            title: 'Packages',
            columns: agentOs === 'windows' ? [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'architecture',
              label: 'Architecture'
            }, {
              id: 'version',
              label: 'Version'
            }, {
              id: 'vendor',
              label: 'Vendor'
            }] : [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'architecture',
              label: 'Architecture'
            }, {
              id: 'version',
              label: 'Version'
            }, {
              id: 'vendor',
              label: 'Vendor'
            }, {
              id: 'description',
              label: 'Description'
            }]
          }
        }, {
          endpoint: `/syscollector/${agentID}/processes`,
          loggerMessage: `Fetching processes for agent ${agentID}`,
          table: {
            title: 'Processes',
            columns: agentOs === 'windows' ? [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'cmd',
              label: 'CMD'
            }, {
              id: 'priority',
              label: 'Priority'
            }, {
              id: 'nlwp',
              label: 'NLWP'
            }] : [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'euser',
              label: 'Effective user'
            }, {
              id: 'nice',
              label: 'Priority'
            }, {
              id: 'state',
              label: 'State'
            }]
          },
          mapResponseItems: item => agentOs === 'windows' ? item : { ...item,
            state: _processStateEquivalence.default[item.state]
          }
        }, {
          endpoint: `/syscollector/${agentID}/ports`,
          loggerMessage: `Fetching ports for agent ${agentID}`,
          table: {
            title: 'Network ports',
            columns: agentOs === 'windows' ? [{
              id: 'local_ip',
              label: 'Local IP address'
            }, {
              id: 'local_port',
              label: 'Local port'
            }, {
              id: 'process',
              label: 'Process'
            }, {
              id: 'state',
              label: 'State'
            }, {
              id: 'protocol',
              label: 'Protocol'
            }] : [{
              id: 'local_ip',
              label: 'Local IP address'
            }, {
              id: 'local_port',
              label: 'Local port'
            }, {
              id: 'state',
              label: 'State'
            }, {
              id: 'protocol',
              label: 'Protocol'
            }]
          },
          mapResponseItems: item => ({ ...item,
            local_ip: item.local.ip,
            local_port: item.local.port
          })
        }, {
          endpoint: `/syscollector/${agentID}/netiface`,
          loggerMessage: `Fetching netiface for agent ${agentID}`,
          table: {
            title: 'Network interfaces',
            columns: [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'mac',
              label: 'Mac'
            }, {
              id: 'state',
              label: 'State'
            }, {
              id: 'mtu',
              label: 'MTU'
            }, {
              id: 'type',
              label: 'Type'
            }]
          }
        }, {
          endpoint: `/syscollector/${agentID}/netaddr`,
          loggerMessage: `Fetching netaddr for agent ${agentID}`,
          table: {
            title: 'Network settings',
            columns: [{
              id: 'iface',
              label: 'Interface'
            }, {
              id: 'address',
              label: 'Address'
            }, {
              id: 'netmask',
              label: 'Netmask'
            }, {
              id: 'proto',
              label: 'Protocol'
            }, {
              id: 'broadcast',
              label: 'Broadcast'
            }]
          }
        }];
        agentOs === 'windows' && agentRequestsInventory.push({
          endpoint: `/syscollector/${agentID}/hotfixes`,
          loggerMessage: `Fetching hotfixes for agent ${agentID}`,
          table: {
            title: 'Windows updates',
            columns: [{
              id: 'hotfix',
              label: 'Update code'
            }]
          }
        });

        const requestInventory = async agentRequestInventory => {
          try {
            (0, _logger.log)('reporting:createReportsAgentsInventory', agentRequestInventory.loggerMessage, 'debug');
            const inventoryResponse = await context.wazuh.api.client.asCurrentUser.request('GET', agentRequestInventory.endpoint, {}, {
              apiHostID: apiId
            });
            const inventory = inventoryResponse && inventoryResponse.data && inventoryResponse.data.data && inventoryResponse.data.data.affected_items;

            if (inventory) {
              return { ...agentRequestInventory.table,
                items: agentRequestInventory.mapResponseItems ? inventory.map(agentRequestInventory.mapResponseItems) : inventory
              };
            }
          } catch (error) {
            (0, _logger.log)('reporting:createReportsAgentsInventory', error.message || error, 'debug');
          }
        };

        if (time) {
          await (0, _extendedInformation.extendedInformation)(context, printer, 'agents', 'syscollector', apiId, from, to, sanitizedFilters + ' AND rule.groups: "vulnerability-detector"', agentsFilter, indexPatternTitle, agentID);
        } // Add inventory tables


        (await Promise.all(agentRequestsInventory.map(requestInventory))).filter(table => table).forEach(table => printer.addSimpleTable(table)); // Print the document

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:createReportsAgents', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      params: {
        agentID
      }
    }) => `wazuh-agent-inventory-${agentID}-${this.generateReportTimestamp()}.pdf`));

    _defineProperty(this, "getReportByName", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:getReportByName', `Getting ${context.wazuhEndpointParams.pathFilename} report`, 'debug');

        const reportFileBuffer = _fs.default.readFileSync(context.wazuhEndpointParams.pathFilename);

        return response.ok({
          headers: {
            'Content-Type': 'application/pdf'
          },
          body: reportFileBuffer
        });
      } catch (error) {
        (0, _logger.log)('reporting:getReportByName', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5030, 500, response);
      }
    }, request => request.params.name));

    _defineProperty(this, "deleteReportByName", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:deleteReportByName', `Deleting ${context.wazuhEndpointParams.pathFilename} report`, 'debug');

        _fs.default.unlinkSync(context.wazuhEndpointParams.pathFilename);

        (0, _logger.log)('reporting:deleteReportByName', `${context.wazuhEndpointParams.pathFilename} report was deleted`, 'info');
        return response.ok({
          body: {
            error: 0
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:deleteReportByName', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5032, 500, response);
      }
    }, request => request.params.name));
  }
  /**
   * This do format to filters
   * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
   * @param {String} searchBar search term
   */


  sanitizeKibanaFilters(filters, searchBar) {
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `Started to sanitize filters`, 'info');
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `filters: ${filters.length}, searchBar: ${searchBar}`, 'debug');
    let str = '';
    const agentsFilter = {
      query: {},
      agentsText: ''
    };
    const agentsList = []; //separate agents filter

    filters = filters.filter(filter => {
      if (filter.meta.controlledBy === _constants.AUTHORIZED_AGENTS) {
        agentsFilter.query = filter.query;
        agentsList.push(filter);
        return false;
      }

      return filter;
    });
    const len = filters.length;

    for (let i = 0; i < len; i++) {
      const {
        negate,
        key,
        value,
        params,
        type
      } = filters[i].meta;
      str += `${negate ? 'NOT ' : ''}`;
      str += `${key}: `;
      str += `${type === 'range' ? `${params.gte}-${params.lt}` : type === 'phrases' ? '(' + params.join(" OR ") + ')' : type === 'exists' ? '*' : !!value ? value : (params || {}).query}`;
      str += `${i === len - 1 ? '' : ' AND '}`;
    }

    if (searchBar) {
      str += ` AND (${searchBar})`;
    }

    agentsFilter.agentsText = agentsList.map(filter => filter.meta.value).join(',');
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `str: ${str}, agentsFilterStr: ${agentsFilter.agentsText}`, 'debug');
    return [str, agentsFilter];
  }
  /**
   * This performs the rendering of given header
   * @param {String} printer section target
   * @param {String} section section target
   * @param {Object} tab tab target
   * @param {Boolean} isAgents is agents section
   * @param {String} apiId ID of API
   */


  async renderHeader(context, printer, section, tab, isAgents, apiId) {
    try {
      (0, _logger.log)('reporting:renderHeader', `section: ${section}, tab: ${tab}, isAgents: ${isAgents}, apiId: ${apiId}`, 'debug');

      if (section && typeof section === 'string') {
        if (!['agentConfig', 'groupConfig'].includes(section)) {
          printer.addContent({
            text: _wazuhModules.WAZUH_MODULES[tab].title + ' report',
            style: 'h1'
          });
        } else if (section === 'agentConfig') {
          printer.addContent({
            text: `Agent ${isAgents} configuration`,
            style: 'h1'
          });
        } else if (section === 'groupConfig') {
          printer.addContent({
            text: 'Agents in group',
            style: 'h1'
          });
        }

        printer.addNewLine();
      }

      if (isAgents && typeof isAgents === 'object') {
        await (0, _extendedInformation.buildAgentsTable)(context, printer, isAgents, apiId, section === 'groupConfig' ? tab : '');
      }

      if (isAgents && typeof isAgents === 'string') {
        const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents`, {
          params: {
            agents_list: isAgents
          }
        }, {
          apiHostID: apiId
        });
        const agentData = agentResponse.data.data.affected_items[0];

        if (agentData && agentData.status !== _constants.API_NAME_AGENT_STATUS.ACTIVE) {
          printer.addContentWithNewLine({
            text: `Warning. Agent is ${(0, _wz_agent_status.agentStatusLabelByAgentStatus)(agentData.status).toLowerCase()}`,
            style: 'standard'
          });
        }

        await (0, _extendedInformation.buildAgentsTable)(context, printer, [isAgents], apiId);

        if (agentData && agentData.group) {
          const agentGroups = agentData.group.join(', ');
          printer.addContentWithNewLine({
            text: `Group${agentData.group.length > 1 ? 's' : ''}: ${agentGroups}`,
            style: 'standard'
          });
        }
      }

      if (_wazuhModules.WAZUH_MODULES[tab] && _wazuhModules.WAZUH_MODULES[tab].description) {
        printer.addContentWithNewLine({
          text: _wazuhModules.WAZUH_MODULES[tab].description,
          style: 'standard'
        });
      }
    } catch (error) {
      (0, _logger.log)('reporting:renderHeader', error.message || error);
      return Promise.reject(error);
    }
  }

  getConfigRows(data, labels) {
    (0, _logger.log)('reporting:getConfigRows', `Building configuration rows`, 'info');
    const result = [];

    for (let prop in data || []) {
      if (Array.isArray(data[prop])) {
        data[prop].forEach((x, idx) => {
          if (typeof x === 'object') data[prop][idx] = JSON.stringify(x);
        });
      }

      result.push([(labels || {})[prop] || _csvKeyEquivalence.KeyEquivalence[prop] || prop, data[prop] || '-']);
    }

    return result;
  }

  getConfigTables(data, section, tab, array = []) {
    (0, _logger.log)('reporting:getConfigTables', `Building configuration tables`, 'info');
    let plainData = {};
    const nestedData = [];
    const tableData = [];

    if (data.length === 1 && Array.isArray(data)) {
      tableData[section.config[tab].configuration] = data;
    } else {
      for (let key in data) {
        if (typeof data[key] !== 'object' && !Array.isArray(data[key]) || Array.isArray(data[key]) && typeof data[key][0] !== 'object') {
          plainData[key] = Array.isArray(data[key]) && typeof data[key][0] !== 'object' ? data[key].map(x => {
            return typeof x === 'object' ? JSON.stringify(x) : x + '\n';
          }) : data[key];
        } else if (Array.isArray(data[key]) && typeof data[key][0] === 'object') {
          tableData[key] = data[key];
        } else {
          if (section.isGroupConfig && ['pack', 'content'].includes(key)) {
            tableData[key] = [data[key]];
          } else {
            nestedData.push(data[key]);
          }
        }
      }
    }

    array.push({
      title: (section.options || {}).hideHeader ? '' : (section.tabs || [])[tab] || (section.isGroupConfig ? ((section.labels || [])[0] || [])[tab] : ''),
      columns: ['', ''],
      type: 'config',
      rows: this.getConfigRows(plainData, (section.labels || [])[0])
    });

    for (let key in tableData) {
      const columns = Object.keys(tableData[key][0]);
      columns.forEach((col, i) => {
        columns[i] = col[0].toUpperCase() + col.slice(1);
      });
      const rows = tableData[key].map(x => {
        let row = [];

        for (let key in x) {
          row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
            return x + '\n';
          }) : JSON.stringify(x[key]));
        }

        while (row.length < columns.length) {
          row.push('-');
        }

        return row;
      });
      array.push({
        title: ((section.labels || [])[0] || [])[key] || '',
        type: 'table',
        columns,
        rows
      });
    }

    nestedData.forEach(nest => {
      this.getConfigTables(nest, section, tab + 1, array);
    });
    return array;
  }
  /**
   * Create a report for the modules
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {*} reports list or ErrorResponse
   */


  /**
   * Fetch the reports list
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<Object>} reports list or ErrorResponse
   */
  async getReports(context, request, response) {
    try {
      (0, _logger.log)('reporting:getReports', `Fetching created reports`, 'info');
      const {
        hashUsername
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);

      const userReportsDirectoryPath = _path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, hashUsername);

      (0, _filesystem.createDirectoryIfNotExists)(userReportsDirectoryPath);
      (0, _logger.log)('reporting:getReports', `Directory: ${userReportsDirectoryPath}`, 'debug');

      const sortReportsByDate = (a, b) => a.date < b.date ? 1 : a.date > b.date ? -1 : 0;

      const reports = _fs.default.readdirSync(userReportsDirectoryPath).map(file => {
        const stats = _fs.default.statSync(userReportsDirectoryPath + '/' + file); // Get the file creation time (bithtime). It returns the first value that is a truthy value of next file stats: birthtime, mtime, ctime and atime.
        // This solves some OSs can have the bithtimeMs equal to 0 and returns the date like 1970-01-01


        const birthTimeField = ['birthtime', 'mtime', 'ctime', 'atime'].find(time => stats[`${time}Ms`]);
        return {
          name: file,
          size: stats.size,
          date: stats[birthTimeField]
        };
      });

      (0, _logger.log)('reporting:getReports', `Using TimSort for sorting ${reports.length} items`, 'debug');
      TimSort.sort(reports, sortReportsByDate);
      (0, _logger.log)('reporting:getReports', `Total reports: ${reports.length}`, 'debug');
      return response.ok({
        body: {
          reports
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:getReports', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5031, 500, response);
    }
  }
  /**
   * Fetch specific report
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} report or ErrorResponse
   */


  checkReportsUserDirectoryIsValidRouteDecorator(routeHandler, reportFileNameAccessor) {
    return async (context, request, response) => {
      try {
        const {
          username,
          hashUsername
        } = await context.wazuh.security.getCurrentUser(request, context);

        const userReportsDirectoryPath = _path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, hashUsername);

        const filename = reportFileNameAccessor(request);

        const pathFilename = _path.default.join(userReportsDirectoryPath, filename);

        (0, _logger.log)('reporting:checkReportsUserDirectoryIsValidRouteDecorator', `Checking the user ${username}(${hashUsername}) can do actions in the reports file: ${pathFilename}`, 'debug');

        if (!pathFilename.startsWith(userReportsDirectoryPath) || pathFilename.includes('../')) {
          (0, _logger.log)('security:reporting:checkReportsUserDirectoryIsValidRouteDecorator', `User ${username}(${hashUsername}) tried to access to a non user report file: ${pathFilename}`, 'warn');
          return response.badRequest({
            body: {
              message: '5040 - You shall not pass!'
            }
          });
        }

        ;
        (0, _logger.log)('reporting:checkReportsUserDirectoryIsValidRouteDecorator', 'Checking the user can do actions in the reports file', 'debug');
        return await routeHandler.bind(this)({ ...context,
          wazuhEndpointParams: {
            hashUsername,
            filename,
            pathFilename
          }
        }, request, response);
      } catch (error) {
        (0, _logger.log)('reporting:checkReportsUserDirectoryIsValidRouteDecorator', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5040, 500, response);
      }
    };
  }

  generateReportTimestamp() {
    return `${Date.now() / 1000 | 0}`;
  }

}

exports.WazuhReportingCtrl = WazuhReportingCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLXJlcG9ydGluZy50cyJdLCJuYW1lcyI6WyJXYXp1aFJlcG9ydGluZ0N0cmwiLCJjb25zdHJ1Y3RvciIsImNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IiLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiYXJyYXkiLCJhZ2VudHMiLCJicm93c2VyVGltZXpvbmUiLCJzZWFyY2hCYXIiLCJmaWx0ZXJzIiwidGltZSIsInRhYmxlcyIsInNlY3Rpb24iLCJpbmRleFBhdHRlcm5UaXRsZSIsImFwaUlkIiwiYm9keSIsIm1vZHVsZUlEIiwicGFyYW1zIiwiZnJvbSIsInRvIiwiYWRkaXRpb25hbFRhYmxlcyIsInByaW50ZXIiLCJSZXBvcnRQcmludGVyIiwiV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgiLCJXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIIiwicGF0aCIsImpvaW4iLCJ3YXp1aEVuZHBvaW50UGFyYW1zIiwiaGFzaFVzZXJuYW1lIiwicmVuZGVySGVhZGVyIiwic2FuaXRpemVkRmlsdGVycyIsImFnZW50c0ZpbHRlciIsInNhbml0aXplS2liYW5hRmlsdGVycyIsImFkZFRpbWVSYW5nZUFuZEZpbHRlcnMiLCJEYXRlIiwiZ2V0VGltZSIsImFkZFZpc3VhbGl6YXRpb25zIiwiYWRkVGFibGVzIiwiYWdlbnRzVGV4dCIsImFkZEFnZW50c0ZpbHRlcnMiLCJwcmludCIsInBhdGhGaWxlbmFtZSIsIm9rIiwic3VjY2VzcyIsIm1lc3NhZ2UiLCJmaWxlbmFtZSIsImVycm9yIiwiZ2VuZXJhdGVSZXBvcnRUaW1lc3RhbXAiLCJjb21wb25lbnRzIiwiZ3JvdXBJRCIsImVxdWl2YWxlbmNlcyIsImxvY2FsZmlsZSIsIm9zcXVlcnkiLCJjb21tYW5kIiwic3lzY2hlY2siLCJzeXNjb2xsZWN0b3IiLCJyb290Y2hlY2siLCJsYWJlbHMiLCJzY2EiLCJhZGRDb250ZW50IiwidGV4dCIsInN0eWxlIiwiZGF0YSIsImNvbmZpZ3VyYXRpb24iLCJ3YXp1aCIsImFwaSIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJhcGlIb3N0SUQiLCJhZmZlY3RlZF9pdGVtcyIsImxlbmd0aCIsIk9iamVjdCIsImtleXMiLCJjb25maWciLCJmb250U2l6ZSIsImNvbG9yIiwibWFyZ2luIiwiaXNHcm91cENvbmZpZyIsImZpbHRlclRpdGxlIiwiaW5kZXgiLCJmaWx0ZXIiLCJjb25jYXQiLCJpZHgiLCJ0YWJzIiwiX2QiLCJjIiwiQWdlbnRDb25maWd1cmF0aW9uIiwiY29uZmlndXJhdGlvbnMiLCJzIiwic2VjdGlvbnMiLCJvcHRzIiwiY24iLCJ3byIsIndvZGxlIiwibmFtZSIsInB1c2giLCJBcnJheSIsImlzQXJyYXkiLCJncm91cHMiLCJmb3JFYWNoIiwib2JqIiwibG9nZm9ybWF0IiwiZ3JvdXAiLCJzYXZlaWR4IiwieCIsImkiLCJjb2x1bW5zIiwicm93cyIsIm1hcCIsInJvdyIsImtleSIsIkpTT04iLCJzdHJpbmdpZnkiLCJjb2wiLCJ0b1VwcGVyQ2FzZSIsInNsaWNlIiwidGl0bGUiLCJ0eXBlIiwibGFiZWwiLCJpbmNsdWRlcyIsIl9kMiIsImdldENvbmZpZ1RhYmxlcyIsImRpcmVjdG9yaWVzIiwiZGlmZk9wdHMiLCJ5IiwicmVjdXJzaW9uX2xldmVsIiwidGFibGUiLCJhZGRDb25maWdUYWJsZXMiLCJhZ2VudElEIiwid21vZHVsZXNSZXNwb25zZSIsImlkeENvbXBvbmVudCIsInRpdGxlT2ZTZWN0aW9uIiwidGl0bGVPZlN1YnNlY3Rpb24iLCJjb25maWdzIiwiY29uZiIsImFnZW50Q29uZmlnUmVzcG9uc2UiLCJjb21wb25lbnQiLCJhZ2VudENvbmZpZyIsInN1YnRpdGxlIiwiZGVzYyIsImFnZW50Q29uZmlnS2V5IiwiZmlsdGVyQnkiLCJtYXRyaXgiLCJkaWZmIiwic3luY2hyb25pemF0aW9uIiwiZmlsZV9saW1pdCIsInJlc3QiLCJkaXNrX3F1b3RhIiwiZmlsZV9zaXplIiwiZGlyIiwiaW5kZXhPZiIsInRvTG93ZXJDYXNlIiwibGluayIsImRvY3VMaW5rIiwic2VjdXJpdHkiLCJnZXRDdXJyZW50VXNlciIsImFnZW50T3MiLCJhZ2VudFJlc3BvbnNlIiwicSIsIm9zIiwicGxhdGZvcm0iLCJhZGRDb250ZW50V2l0aE5ld0xpbmUiLCJhZ2VudFJlcXVlc3RzSW52ZW50b3J5IiwiZW5kcG9pbnQiLCJsb2dnZXJNZXNzYWdlIiwiaWQiLCJtYXBSZXNwb25zZUl0ZW1zIiwiaXRlbSIsInN0YXRlIiwiUHJvY2Vzc0VxdWl2YWxlbmNlIiwibG9jYWxfaXAiLCJsb2NhbCIsImlwIiwibG9jYWxfcG9ydCIsInBvcnQiLCJyZXF1ZXN0SW52ZW50b3J5IiwiYWdlbnRSZXF1ZXN0SW52ZW50b3J5IiwiaW52ZW50b3J5UmVzcG9uc2UiLCJpbnZlbnRvcnkiLCJpdGVtcyIsIlByb21pc2UiLCJhbGwiLCJhZGRTaW1wbGVUYWJsZSIsInJlcG9ydEZpbGVCdWZmZXIiLCJmcyIsInJlYWRGaWxlU3luYyIsImhlYWRlcnMiLCJ1bmxpbmtTeW5jIiwic3RyIiwicXVlcnkiLCJhZ2VudHNMaXN0IiwibWV0YSIsImNvbnRyb2xsZWRCeSIsIkFVVEhPUklaRURfQUdFTlRTIiwibGVuIiwibmVnYXRlIiwidmFsdWUiLCJndGUiLCJsdCIsInRhYiIsImlzQWdlbnRzIiwiV0FaVUhfTU9EVUxFUyIsImFkZE5ld0xpbmUiLCJhZ2VudHNfbGlzdCIsImFnZW50RGF0YSIsInN0YXR1cyIsIkFQSV9OQU1FX0FHRU5UX1NUQVRVUyIsIkFDVElWRSIsImFnZW50R3JvdXBzIiwiZGVzY3JpcHRpb24iLCJyZWplY3QiLCJnZXRDb25maWdSb3dzIiwicmVzdWx0IiwicHJvcCIsIktleUVxdWl2YWxlbmNlIiwicGxhaW5EYXRhIiwibmVzdGVkRGF0YSIsInRhYmxlRGF0YSIsIm9wdGlvbnMiLCJoaWRlSGVhZGVyIiwibmVzdCIsImdldFJlcG9ydHMiLCJ1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGgiLCJzb3J0UmVwb3J0c0J5RGF0ZSIsImEiLCJiIiwiZGF0ZSIsInJlcG9ydHMiLCJyZWFkZGlyU3luYyIsImZpbGUiLCJzdGF0cyIsInN0YXRTeW5jIiwiYmlydGhUaW1lRmllbGQiLCJmaW5kIiwic2l6ZSIsIlRpbVNvcnQiLCJzb3J0Iiwicm91dGVIYW5kbGVyIiwicmVwb3J0RmlsZU5hbWVBY2Nlc3NvciIsInVzZXJuYW1lIiwic3RhcnRzV2l0aCIsImJhZFJlcXVlc3QiLCJiaW5kIiwibm93Il0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBRUE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBTUE7O0FBQ0E7Ozs7Ozs7Ozs7QUFPTyxNQUFNQSxrQkFBTixDQUF5QjtBQUM5QkMsRUFBQUEsV0FBVyxHQUFHO0FBQUEsa0RBa1BTLEtBQUtDLDhDQUFMLENBQW9ELE9BQ3pFQyxPQUR5RSxFQUV6RUMsT0FGeUUsRUFHekVDLFFBSHlFLEtBSXRFO0FBQ0gsVUFBSTtBQUNGLHlCQUFJLGdDQUFKLEVBQXVDLGdCQUF2QyxFQUF3RCxNQUF4RDtBQUNBLGNBQU07QUFDSkMsVUFBQUEsS0FESTtBQUVKQyxVQUFBQSxNQUZJO0FBR0pDLFVBQUFBLGVBSEk7QUFJSkMsVUFBQUEsU0FKSTtBQUtKQyxVQUFBQSxPQUxJO0FBTUpDLFVBQUFBLElBTkk7QUFPSkMsVUFBQUEsTUFQSTtBQVFKQyxVQUFBQSxPQVJJO0FBU0pDLFVBQUFBLGlCQVRJO0FBVUpDLFVBQUFBO0FBVkksWUFXRlgsT0FBTyxDQUFDWSxJQVhaO0FBWUEsY0FBTTtBQUFFQyxVQUFBQTtBQUFGLFlBQWViLE9BQU8sQ0FBQ2MsTUFBN0I7QUFDQSxjQUFNO0FBQUVDLFVBQUFBLElBQUY7QUFBUUMsVUFBQUE7QUFBUixZQUFlVCxJQUFJLElBQUksRUFBN0I7QUFDQSxZQUFJVSxnQkFBZ0IsR0FBRyxFQUF2QixDQWhCRSxDQWlCRjs7QUFDQSxjQUFNQyxPQUFPLEdBQUcsSUFBSUMsc0JB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LE1BQXpLO0FBQ0EsaUJBQU9yQyxRQUFRLENBQUM2TyxVQUFULENBQW9CO0FBQ3pCbE8sWUFBQUEsSUFBSSxFQUFFO0FBQ0o2QixjQUFBQSxPQUFPLEVBQUU7QUFETDtBQURtQixXQUFwQixDQUFQO0FBS0Q7O0FBQUE7QUFDRCx5QkFBSSwwREFBSixFQUFnRSxzREFBaEUsRUFBd0gsT0FBeEg7QUFDQSxlQUFPLE1BQU1pTSxZQUFZLENBQUNLLElBQWIsQ0FBa0IsSUFBbEIsRUFBd0IsRUFBQyxHQUFHaFAsT0FBSjtBQUFheUIsVUFBQUEsbUJBQW1CLEVBQUU7QUFBRUMsWUFBQUEsWUFBRjtBQUFnQmlCLFlBQUFBLFFBQWhCO0FBQTBCSixZQUFBQTtBQUExQjtBQUFsQyxTQUF4QixFQUFxR3RDLE9BQXJHLEVBQThHQyxRQUE5RyxDQUFiO0FBQ0QsT0FoQkQsQ0FnQkMsT0FBTTBDLEtBQU4sRUFBWTtBQUNYLHlCQUFJLDBEQUFKLEVBQWdFQSxLQUFLLENBQUNGLE9BQU4sSUFBaUJFLEtBQWpGO0FBQ0EsZUFBTyxrQ0FBY0EsS0FBSyxDQUFDRixPQUFOLElBQWlCRSxLQUEvQixFQUFzQyxJQUF0QyxFQUE0QyxHQUE1QyxFQUFpRDFDLFFBQWpELENBQVA7QUFDRDtBQUNGLEtBekJEO0FBMEJEOztBQUVPMkMsRUFBQUEsdUJBQXVCLEdBQUU7QUFDL0IsV0FBUSxHQUFHYixJQUFJLENBQUNpTixHQUFMLEtBQWEsSUFBZCxHQUFzQixDQUFFLEVBQWxDO0FBQ0Q7O0FBeHFDNkIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gQ2xhc3MgZm9yIFdhenVoIHJlcG9ydGluZyBjb250cm9sbGVyXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHBhdGggZnJvbSAncGF0aCc7XG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHsgV0FaVUhfTU9EVUxFUyB9IGZyb20gJy4uLy4uL2NvbW1vbi93YXp1aC1tb2R1bGVzJztcbmltcG9ydCAqIGFzIFRpbVNvcnQgZnJvbSAndGltc29ydCc7XG5pbXBvcnQgeyBFcnJvclJlc3BvbnNlIH0gZnJvbSAnLi4vbGliL2Vycm9yLXJlc3BvbnNlJztcbmltcG9ydCBQcm9jZXNzRXF1aXZhbGVuY2UgZnJvbSAnLi4vbGliL3Byb2Nlc3Mtc3RhdGUtZXF1aXZhbGVuY2UnO1xuaW1wb3J0IHsgS2V5RXF1aXZhbGVuY2UgfSBmcm9tICcuLi8uLi9jb21tb24vY3N2LWtleS1lcXVpdmFsZW5jZSc7XG5pbXBvcnQgeyBBZ2VudENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9saWIvcmVwb3J0aW5nL2FnZW50LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5IH0gZnJvbSAnc3JjL2NvcmUvc2VydmVyJztcbmltcG9ydCB7IGV4dGVuZGVkSW5mb3JtYXRpb24sIGJ1aWxkQWdlbnRzVGFibGUgfSBmcm9tICcuLi9saWIvcmVwb3J0aW5nL2V4dGVuZGVkLWluZm9ybWF0aW9uJztcbmltcG9ydCB7IFJlcG9ydFByaW50ZXIgfSBmcm9tICcuLi9saWIvcmVwb3J0aW5nL3ByaW50ZXInO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQge1xuICBXQVpVSF9EQVRBX0RPV05MT0FEU19ESVJFQ1RPUllfUEFUSCxcbiAgV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCxcbiAgQVVUSE9SSVpFRF9BR0VOVFMsXG4gIEFQSV9OQU1FX0FHRU5UX1NUQVRVUyxcbn0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cywgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzIH0gZnJvbSAnLi4vbGliL2ZpbGVzeXN0ZW0nO1xuaW1wb3J0IHsgYWdlbnRTdGF0dXNMYWJlbEJ5QWdlbnRTdGF0dXMgfSBmcm9tICcuLi8uLi9jb21tb24vc2VydmljZXMvd3pfYWdlbnRfc3RhdHVzJztcblxuaW50ZXJmYWNlIEFnZW50c0ZpbHRlciB7XG4gIHF1ZXJ5OiBhbnk7XG4gIGFnZW50c1RleHQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGNsYXNzIFdhenVoUmVwb3J0aW5nQ3RybCB7XG4gIGNvbnN0cnVjdG9yKCkge31cbiAgLyoqXG4gICAqIFRoaXMgZG8gZm9ybWF0IHRvIGZpbHRlcnNcbiAgICogQHBhcmFtIHtTdHJpbmd9IGZpbHRlcnMgRS5nOiBjbHVzdGVyLm5hbWU6IHdhenVoIEFORCBydWxlLmdyb3VwczogdnVsbmVyYWJpbGl0eVxuICAgKiBAcGFyYW0ge1N0cmluZ30gc2VhcmNoQmFyIHNlYXJjaCB0ZXJtXG4gICAqL1xuICBwcml2YXRlIHNhbml0aXplS2liYW5hRmlsdGVycyhmaWx0ZXJzOiBhbnksIHNlYXJjaEJhcj86IHN0cmluZyk6IFtzdHJpbmcsIEFnZW50c0ZpbHRlcl0ge1xuICAgIGxvZygncmVwb3J0aW5nOnNhbml0aXplS2liYW5hRmlsdGVycycsIGBTdGFydGVkIHRvIHNhbml0aXplIGZpbHRlcnNgLCAnaW5mbycpO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6c2FuaXRpemVLaWJhbmFGaWx0ZXJzJyxcbiAgICAgIGBmaWx0ZXJzOiAke2ZpbHRlcnMubGVuZ3RofSwgc2VhcmNoQmFyOiAke3NlYXJjaEJhcn1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gICAgbGV0IHN0ciA9ICcnO1xuXG4gICAgY29uc3QgYWdlbnRzRmlsdGVyOiBBZ2VudHNGaWx0ZXIgPSB7IHF1ZXJ5OiB7fSwgYWdlbnRzVGV4dDogJycgfTtcbiAgICBjb25zdCBhZ2VudHNMaXN0OiBzdHJpbmdbXSA9IFtdO1xuXG4gICAgLy9zZXBhcmF0ZSBhZ2VudHMgZmlsdGVyXG4gICAgZmlsdGVycyA9IGZpbHRlcnMuZmlsdGVyKChmaWx0ZXIpID0+IHtcbiAgICAgIGlmIChmaWx0ZXIubWV0YS5jb250cm9sbGVkQnkgPT09IEFVVEhPUklaRURfQUdFTlRTKSB7XG4gICAgICAgIGFnZW50c0ZpbHRlci5xdWVyeSA9IGZpbHRlci5xdWVyeTtcbiAgICAgICAgYWdlbnRzTGlzdC5wdXNoKGZpbHRlcik7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBmaWx0ZXI7XG4gICAgfSk7XG5cbiAgICBjb25zdCBsZW4gPSBmaWx0ZXJzLmxlbmd0aDtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIGNvbnN0IHsgbmVnYXRlLCBrZXksIHZhbHVlLCBwYXJhbXMsIHR5cGUgfSA9IGZpbHRlcnNbaV0ubWV0YTtcbiAgICAgIHN0ciArPSBgJHtuZWdhdGUgPyAnTk9UICcgOiAnJ31gO1xuICAgICAgc3RyICs9IGAke2tleX06IGA7XG4gICAgICBzdHIgKz0gYCR7XG4gICAgICAgIHR5cGUgPT09ICdyYW5nZSdcbiAgICAgICAgICA/IGAke3BhcmFtcy5ndGV9LSR7cGFyYW1zLmx0fWBcbiAgICAgICAgICA6IHR5cGUgPT09ICdwaHJhc2VzJ1xuICAgICAgICAgICAgPyAnKCcgKyBwYXJhbXMuam9pbihcIiBPUiBcIikgKyAnKSdcbiAgICAgICAgICAgIDogdHlwZSA9PT0gJ2V4aXN0cydcbiAgICAgICAgICAgICAgPyAnKidcbiAgICAgICAgICAgICAgOiAhIXZhbHVlXG4gICAgICAgICAgPyB2YWx1ZVxuICAgICAgICAgIDogKHBhcmFtcyB8fCB7fSkucXVlcnlcbiAgICAgIH1gO1xuICAgICAgc3RyICs9IGAke2kgPT09IGxlbiAtIDEgPyAnJyA6ICcgQU5EICd9YDtcbiAgICB9XG5cbiAgICBpZiAoc2VhcmNoQmFyKSB7XG4gICAgICBzdHIgKz0gYCBBTkQgKCR7IHNlYXJjaEJhcn0pYDtcbiAgICB9XG5cbiAgICBhZ2VudHNGaWx0ZXIuYWdlbnRzVGV4dCA9IGFnZW50c0xpc3QubWFwKChmaWx0ZXIpID0+IGZpbHRlci5tZXRhLnZhbHVlKS5qb2luKCcsJyk7XG5cbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnNhbml0aXplS2liYW5hRmlsdGVycycsXG4gICAgICBgc3RyOiAke3N0cn0sIGFnZW50c0ZpbHRlclN0cjogJHthZ2VudHNGaWx0ZXIuYWdlbnRzVGV4dH1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICByZXR1cm4gW3N0ciwgYWdlbnRzRmlsdGVyXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHBlcmZvcm1zIHRoZSByZW5kZXJpbmcgb2YgZ2l2ZW4gaGVhZGVyXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwcmludGVyIHNlY3Rpb24gdGFyZ2V0XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBzZWN0aW9uIHNlY3Rpb24gdGFyZ2V0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSB0YWIgdGFiIHRhcmdldFxuICAgKiBAcGFyYW0ge0Jvb2xlYW59IGlzQWdlbnRzIGlzIGFnZW50cyBzZWN0aW9uXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBhcGlJZCBJRCBvZiBBUElcbiAgICovXG4gIHByaXZhdGUgYXN5bmMgcmVuZGVySGVhZGVyKGNvbnRleHQsIHByaW50ZXIsIHNlY3Rpb24sIHRhYiwgaXNBZ2VudHMsIGFwaUlkKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3JlcG9ydGluZzpyZW5kZXJIZWFkZXInLFxuICAgICAgICBgc2VjdGlvbjogJHtzZWN0aW9ufSwgdGFiOiAke3RhYn0sIGlzQWdlbnRzOiAke2lzQWdlbnRzfSwgYXBpSWQ6ICR7YXBpSWR9YCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGlmIChzZWN0aW9uICYmIHR5cGVvZiBzZWN0aW9uID09PSAnc3RyaW5nJykge1xuICAgICAgICBpZiAoIVsnYWdlbnRDb25maWcnLCAnZ3JvdXBDb25maWcnXS5pbmNsdWRlcyhzZWN0aW9uKSkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICB0ZXh0OiBXQVpVSF9NT0RVTEVTW3RhYl0udGl0bGUgKyAnIHJlcG9ydCcsXG4gICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIGlmIChzZWN0aW9uID09PSAnYWdlbnRDb25maWcnKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGBBZ2VudCAke2lzQWdlbnRzfSBjb25maWd1cmF0aW9uYCxcbiAgICAgICAgICAgIHN0eWxlOiAnaDEnLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKHNlY3Rpb24gPT09ICdncm91cENvbmZpZycpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0FnZW50cyBpbiBncm91cCcsXG4gICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGlzQWdlbnRzICYmIHR5cGVvZiBpc0FnZW50cyA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgYXdhaXQgYnVpbGRBZ2VudHNUYWJsZShcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIHByaW50ZXIsXG4gICAgICAgICAgaXNBZ2VudHMsXG4gICAgICAgICAgYXBpSWQsXG4gICAgICAgICAgc2VjdGlvbiA9PT0gJ2dyb3VwQ29uZmlnJyA/IHRhYiA6ICcnXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGlmIChpc0FnZW50cyAmJiB0eXBlb2YgaXNBZ2VudHMgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGNvbnN0IGFnZW50UmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgIGAvYWdlbnRzYCxcbiAgICAgICAgICB7IHBhcmFtczogeyBhZ2VudHNfbGlzdDogaXNBZ2VudHMgfSB9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IGFnZW50RGF0YSA9IGFnZW50UmVzcG9uc2UuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdO1xuICAgICAgICBpZiAoYWdlbnREYXRhICYmIGFnZW50RGF0YS5zdGF0dXMgIT09IEFQSV9OQU1FX0FHRU5UX1NUQVRVUy5BQ1RJVkUpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgICB0ZXh0OiBgV2FybmluZy4gQWdlbnQgaXMgJHthZ2VudFN0YXR1c0xhYmVsQnlBZ2VudFN0YXR1cyhhZ2VudERhdGEuc3RhdHVzKS50b0xvd2VyQ2FzZSgpfWAsXG4gICAgICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBhd2FpdCBidWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIFtpc0FnZW50c10sIGFwaUlkKTtcblxuICAgICAgICBpZiAoYWdlbnREYXRhICYmIGFnZW50RGF0YS5ncm91cCkge1xuICAgICAgICAgIGNvbnN0IGFnZW50R3JvdXBzID0gYWdlbnREYXRhLmdyb3VwLmpvaW4oJywgJyk7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDogYEdyb3VwJHthZ2VudERhdGEuZ3JvdXAubGVuZ3RoID4gMSA/ICdzJyA6ICcnfTogJHthZ2VudEdyb3Vwc31gLFxuICAgICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChXQVpVSF9NT0RVTEVTW3RhYl0gJiYgV0FaVUhfTU9EVUxFU1t0YWJdLmRlc2NyaXB0aW9uKSB7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OiBXQVpVSF9NT0RVTEVTW3RhYl0uZGVzY3JpcHRpb24sXG4gICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJIZWFkZXInLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBnZXRDb25maWdSb3dzKGRhdGEsIGxhYmVscykge1xuICAgIGxvZygncmVwb3J0aW5nOmdldENvbmZpZ1Jvd3MnLCBgQnVpbGRpbmcgY29uZmlndXJhdGlvbiByb3dzYCwgJ2luZm8nKTtcbiAgICBjb25zdCByZXN1bHQgPSBbXTtcbiAgICBmb3IgKGxldCBwcm9wIGluIGRhdGEgfHwgW10pIHtcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KGRhdGFbcHJvcF0pKSB7XG4gICAgICAgIGRhdGFbcHJvcF0uZm9yRWFjaCgoeCwgaWR4KSA9PiB7XG4gICAgICAgICAgaWYgKHR5cGVvZiB4ID09PSAnb2JqZWN0JykgZGF0YVtwcm9wXVtpZHhdID0gSlNPTi5zdHJpbmdpZnkoeCk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgcmVzdWx0LnB1c2goWyhsYWJlbHMgfHwge30pW3Byb3BdIHx8IEtleUVxdWl2YWxlbmNlW3Byb3BdIHx8IHByb3AsIGRhdGFbcHJvcF0gfHwgJy0nXSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBwcml2YXRlIGdldENvbmZpZ1RhYmxlcyhkYXRhLCBzZWN0aW9uLCB0YWIsIGFycmF5ID0gW10pIHtcbiAgICBsb2coJ3JlcG9ydGluZzpnZXRDb25maWdUYWJsZXMnLCBgQnVpbGRpbmcgY29uZmlndXJhdGlvbiB0YWJsZXNgLCAnaW5mbycpO1xuICAgIGxldCBwbGFpbkRhdGEgPSB7fTtcbiAgICBjb25zdCBuZXN0ZWREYXRhID0gW107XG4gICAgY29uc3QgdGFibGVEYXRhID0gW107XG5cbiAgICBpZiAoZGF0YS5sZW5ndGggPT09IDEgJiYgQXJyYXkuaXNBcnJheShkYXRhKSkge1xuICAgICAgdGFibGVEYXRhW3NlY3Rpb24uY29uZmlnW3RhYl0uY29uZmlndXJhdGlvbl0gPSBkYXRhO1xuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGxldCBrZXkgaW4gZGF0YSkge1xuICAgICAgICBpZiAoXG4gICAgICAgICAgKHR5cGVvZiBkYXRhW2tleV0gIT09ICdvYmplY3QnICYmICFBcnJheS5pc0FycmF5KGRhdGFba2V5XSkpIHx8XG4gICAgICAgICAgKEFycmF5LmlzQXJyYXkoZGF0YVtrZXldKSAmJiB0eXBlb2YgZGF0YVtrZXldWzBdICE9PSAnb2JqZWN0JylcbiAgICAgICAgKSB7XG4gICAgICAgICAgcGxhaW5EYXRhW2tleV0gPVxuICAgICAgICAgICAgQXJyYXkuaXNBcnJheShkYXRhW2tleV0pICYmIHR5cGVvZiBkYXRhW2tleV1bMF0gIT09ICdvYmplY3QnXG4gICAgICAgICAgICAgID8gZGF0YVtrZXldLm1hcCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgcmV0dXJuIHR5cGVvZiB4ID09PSAnb2JqZWN0JyA/IEpTT04uc3RyaW5naWZ5KHgpIDogeCArICdcXG4nO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgIDogZGF0YVtrZXldO1xuICAgICAgICB9IGVsc2UgaWYgKEFycmF5LmlzQXJyYXkoZGF0YVtrZXldKSAmJiB0eXBlb2YgZGF0YVtrZXldWzBdID09PSAnb2JqZWN0Jykge1xuICAgICAgICAgIHRhYmxlRGF0YVtrZXldID0gZGF0YVtrZXldO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGlmIChzZWN0aW9uLmlzR3JvdXBDb25maWcgJiYgWydwYWNrJywgJ2NvbnRlbnQnXS5pbmNsdWRlcyhrZXkpKSB7XG4gICAgICAgICAgICB0YWJsZURhdGFba2V5XSA9IFtkYXRhW2tleV1dO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBuZXN0ZWREYXRhLnB1c2goZGF0YVtrZXldKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgYXJyYXkucHVzaCh7XG4gICAgICB0aXRsZTogKHNlY3Rpb24ub3B0aW9ucyB8fCB7fSkuaGlkZUhlYWRlclxuICAgICAgICA/ICcnXG4gICAgICAgIDogKHNlY3Rpb24udGFicyB8fCBbXSlbdGFiXSB8fFxuICAgICAgICAgIChzZWN0aW9uLmlzR3JvdXBDb25maWcgPyAoKHNlY3Rpb24ubGFiZWxzIHx8IFtdKVswXSB8fCBbXSlbdGFiXSA6ICcnKSxcbiAgICAgIGNvbHVtbnM6IFsnJywgJyddLFxuICAgICAgdHlwZTogJ2NvbmZpZycsXG4gICAgICByb3dzOiB0aGlzLmdldENvbmZpZ1Jvd3MocGxhaW5EYXRhLCAoc2VjdGlvbi5sYWJlbHMgfHwgW10pWzBdKSxcbiAgICB9KTtcbiAgICBmb3IgKGxldCBrZXkgaW4gdGFibGVEYXRhKSB7XG4gICAgICBjb25zdCBjb2x1bW5zID0gT2JqZWN0LmtleXModGFibGVEYXRhW2tleV1bMF0pO1xuICAgICAgY29sdW1ucy5mb3JFYWNoKChjb2wsIGkpID0+IHtcbiAgICAgICAgY29sdW1uc1tpXSA9IGNvbFswXS50b1VwcGVyQ2FzZSgpICsgY29sLnNsaWNlKDEpO1xuICAgICAgfSk7XG5cbiAgICAgIGNvbnN0IHJvd3MgPSB0YWJsZURhdGFba2V5XS5tYXAoKHgpID0+IHtcbiAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICBmb3IgKGxldCBrZXkgaW4geCkge1xuICAgICAgICAgIHJvdy5wdXNoKFxuICAgICAgICAgICAgdHlwZW9mIHhba2V5XSAhPT0gJ29iamVjdCdcbiAgICAgICAgICAgICAgPyB4W2tleV1cbiAgICAgICAgICAgICAgOiBBcnJheS5pc0FycmF5KHhba2V5XSlcbiAgICAgICAgICAgICAgPyB4W2tleV0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4geCArICdcXG4nO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgIDogSlNPTi5zdHJpbmdpZnkoeFtrZXldKVxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgICAgd2hpbGUgKHJvdy5sZW5ndGggPCBjb2x1bW5zLmxlbmd0aCkge1xuICAgICAgICAgIHJvdy5wdXNoKCctJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJvdztcbiAgICAgIH0pO1xuICAgICAgYXJyYXkucHVzaCh7XG4gICAgICAgIHRpdGxlOiAoKHNlY3Rpb24ubGFiZWxzIHx8IFtdKVswXSB8fCBbXSlba2V5XSB8fCAnJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgY29sdW1ucyxcbiAgICAgICAgcm93cyxcbiAgICAgIH0pO1xuICAgIH1cbiAgICBuZXN0ZWREYXRhLmZvckVhY2gobmVzdCA9PiB7XG4gICAgICB0aGlzLmdldENvbmZpZ1RhYmxlcyhuZXN0LCBzZWN0aW9uLCB0YWIgKyAxLCBhcnJheSk7XG4gICAgfSk7XG4gICAgcmV0dXJuIGFycmF5O1xuICB9XG5cbiAgLyoqXG4gICAqIENyZWF0ZSBhIHJlcG9ydCBmb3IgdGhlIG1vZHVsZXNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHsqfSByZXBvcnRzIGxpc3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgY3JlYXRlUmVwb3J0c01vZHVsZXMgPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoYXN5bmMgKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsXG4gICAgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5XG4gICkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzTW9kdWxlcycsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7XG4gICAgICAgIGFycmF5LFxuICAgICAgICBhZ2VudHMsXG4gICAgICAgIGJyb3dzZXJUaW1lem9uZSxcbiAgICAgICAgc2VhcmNoQmFyLFxuICAgICAgICBmaWx0ZXJzLFxuICAgICAgICB0aW1lLFxuICAgICAgICB0YWJsZXMsXG4gICAgICAgIHNlY3Rpb24sXG4gICAgICAgIGluZGV4UGF0dGVyblRpdGxlLFxuICAgICAgICBhcGlJZFxuICAgICAgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGNvbnN0IHsgbW9kdWxlSUQgfSA9IHJlcXVlc3QucGFyYW1zO1xuICAgICAgY29uc3QgeyBmcm9tLCB0byB9ID0gdGltZSB8fCB7fTtcbiAgICAgIGxldCBhZGRpdGlvbmFsVGFibGVzID0gW107XG4gICAgICAvLyBJbml0XG4gICAgICBjb25zdCBwcmludGVyID0gbmV3IFJlcG9ydFByaW50ZXIoKTtcblxuICAgICAgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzKCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhXQVpVSF9EQVRBX0RPV05MT0FEU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCBjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMuaGFzaFVzZXJuYW1lKSk7XG5cbiAgICAgIGF3YWl0IHRoaXMucmVuZGVySGVhZGVyKGNvbnRleHQsIHByaW50ZXIsIHNlY3Rpb24sIG1vZHVsZUlELCBhZ2VudHMsIGFwaUlkKTtcblxuICAgICAgY29uc3QgW3Nhbml0aXplZEZpbHRlcnMsIGFnZW50c0ZpbHRlcl0gPSBmaWx0ZXJzXG4gICAgICAgID8gdGhpcy5zYW5pdGl6ZUtpYmFuYUZpbHRlcnMoZmlsdGVycywgc2VhcmNoQmFyKVxuICAgICAgICA6IFtmYWxzZSwgbnVsbF07XG5cbiAgICAgIGlmICh0aW1lICYmIHNhbml0aXplZEZpbHRlcnMpIHtcbiAgICAgICAgcHJpbnRlci5hZGRUaW1lUmFuZ2VBbmRGaWx0ZXJzKGZyb20sIHRvLCBzYW5pdGl6ZWRGaWx0ZXJzLCBicm93c2VyVGltZXpvbmUpO1xuICAgICAgfVxuXG4gICAgICBpZiAodGltZSkge1xuICAgICAgICBhZGRpdGlvbmFsVGFibGVzID0gYXdhaXQgZXh0ZW5kZWRJbmZvcm1hdGlvbihcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIHByaW50ZXIsXG4gICAgICAgICAgc2VjdGlvbixcbiAgICAgICAgICBtb2R1bGVJRCxcbiAgICAgICAgICBhcGlJZCxcbiAgICAgICAgICBuZXcgRGF0ZShmcm9tKS5nZXRUaW1lKCksXG4gICAgICAgICAgbmV3IERhdGUodG8pLmdldFRpbWUoKSxcbiAgICAgICAgICBzYW5pdGl6ZWRGaWx0ZXJzLFxuICAgICAgICAgIGFnZW50c0ZpbHRlcixcbiAgICAgICAgICBpbmRleFBhdHRlcm5UaXRsZSxcbiAgICAgICAgICBhZ2VudHNcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgcHJpbnRlci5hZGRWaXN1YWxpemF0aW9ucyhhcnJheSwgYWdlbnRzLCBtb2R1bGVJRCk7XG5cbiAgICAgIGlmICh0YWJsZXMpIHtcbiAgICAgICAgcHJpbnRlci5hZGRUYWJsZXMoWy4uLnRhYmxlcywgLi4uKGFkZGl0aW9uYWxUYWJsZXMgfHwgW10pXSk7XG4gICAgICB9XG5cbiAgICAgIC8vYWRkIGF1dGhvcml6ZWQgYWdlbnRzXG4gICAgICBpZiAoYWdlbnRzRmlsdGVyPy5hZ2VudHNUZXh0KSB7XG4gICAgICAgIHByaW50ZXIuYWRkQWdlbnRzRmlsdGVycyhhZ2VudHNGaWx0ZXIuYWdlbnRzVGV4dCk7XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHByaW50ZXIucHJpbnQoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMuZmlsZW5hbWV9IHdhcyBjcmVhdGVkYCxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA1MDI5LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH0sKHtib2R5OnsgYWdlbnRzIH0sIHBhcmFtczogeyBtb2R1bGVJRCB9fSkgPT4gYHdhenVoLW1vZHVsZS0ke2FnZW50cyA/IGBhZ2VudHMtJHthZ2VudHN9YCA6ICdvdmVydmlldyd9LSR7bW9kdWxlSUR9LSR7dGhpcy5nZW5lcmF0ZVJlcG9ydFRpbWVzdGFtcCgpfS5wZGZgKVxuXG4gIC8qKlxuICAgKiBDcmVhdGUgYSByZXBvcnQgZm9yIHRoZSBncm91cHNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHsqfSByZXBvcnRzIGxpc3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgY3JlYXRlUmVwb3J0c0dyb3VwcyA9IHRoaXMuY2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvcihhc3luYyhcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeVxuICApID0+IHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0dyb3VwcycsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IGNvbXBvbmVudHMsIGFwaUlkIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICBjb25zdCB7IGdyb3VwSUQgfSA9IHJlcXVlc3QucGFyYW1zO1xuICAgICAgLy8gSW5pdFxuICAgICAgY29uc3QgcHJpbnRlciA9IG5ldyBSZXBvcnRQcmludGVyKCk7XG5cbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLmhhc2hVc2VybmFtZSkpO1xuXG4gICAgICBsZXQgdGFibGVzID0gW107XG4gICAgICBjb25zdCBlcXVpdmFsZW5jZXMgPSB7XG4gICAgICAgIGxvY2FsZmlsZTogJ0xvY2FsIGZpbGVzJyxcbiAgICAgICAgb3NxdWVyeTogJ09zcXVlcnknLFxuICAgICAgICBjb21tYW5kOiAnQ29tbWFuZCcsXG4gICAgICAgIHN5c2NoZWNrOiAnU3lzY2hlY2snLFxuICAgICAgICAnb3Blbi1zY2FwJzogJ09wZW5TQ0FQJyxcbiAgICAgICAgJ2Npcy1jYXQnOiAnQ0lTLUNBVCcsXG4gICAgICAgIHN5c2NvbGxlY3RvcjogJ1N5c2NvbGxlY3RvcicsXG4gICAgICAgIHJvb3RjaGVjazogJ1Jvb3RjaGVjaycsXG4gICAgICAgIGxhYmVsczogJ0xhYmVscycsXG4gICAgICAgIHNjYTogJ1NlY3VyaXR5IGNvbmZpZ3VyYXRpb24gYXNzZXNzbWVudCcsXG4gICAgICB9O1xuICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgdGV4dDogYEdyb3VwICR7Z3JvdXBJRH0gY29uZmlndXJhdGlvbmAsXG4gICAgICAgIHN0eWxlOiAnaDEnLFxuICAgICAgfSk7XG5cbiAgICAgIC8vIEdyb3VwIGNvbmZpZ3VyYXRpb25cbiAgICAgIGlmIChjb21wb25lbnRzWycwJ10pIHtcblxuICAgICAgICBjb25zdCB7IGRhdGE6IHsgZGF0YTogY29uZmlndXJhdGlvbiB9IH0gPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgIGAvZ3JvdXBzLyR7Z3JvdXBJRH0vY29uZmlndXJhdGlvbmAsXG4gICAgICAgICAge30sXG4gICAgICAgICAgeyBhcGlIb3N0SUQ6IGFwaUlkIH1cbiAgICAgICAgKTtcblxuICAgICAgICBpZiAoXG4gICAgICAgICAgY29uZmlndXJhdGlvbi5hZmZlY3RlZF9pdGVtcy5sZW5ndGggPiAwICYmXG4gICAgICAgICAgT2JqZWN0LmtleXMoY29uZmlndXJhdGlvbi5hZmZlY3RlZF9pdGVtc1swXS5jb25maWcpLmxlbmd0aFxuICAgICAgICApIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0NvbmZpZ3VyYXRpb25zJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxNCwgY29sb3I6ICcjMDAwJyB9LFxuICAgICAgICAgICAgbWFyZ2luOiBbMCwgMTAsIDAsIDE1XSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBjb25zdCBzZWN0aW9uID0ge1xuICAgICAgICAgICAgbGFiZWxzOiBbXSxcbiAgICAgICAgICAgIGlzR3JvdXBDb25maWc6IHRydWUsXG4gICAgICAgICAgfTtcbiAgICAgICAgICBmb3IgKGxldCBjb25maWcgb2YgY29uZmlndXJhdGlvbi5hZmZlY3RlZF9pdGVtcykge1xuICAgICAgICAgICAgbGV0IGZpbHRlclRpdGxlID0gJyc7XG4gICAgICAgICAgICBsZXQgaW5kZXggPSAwO1xuICAgICAgICAgICAgZm9yIChsZXQgZmlsdGVyIG9mIE9iamVjdC5rZXlzKGNvbmZpZy5maWx0ZXJzKSkge1xuICAgICAgICAgICAgICBmaWx0ZXJUaXRsZSA9IGZpbHRlclRpdGxlLmNvbmNhdChgJHtmaWx0ZXJ9OiAke2NvbmZpZy5maWx0ZXJzW2ZpbHRlcl19YCk7XG4gICAgICAgICAgICAgIGlmIChpbmRleCA8IE9iamVjdC5rZXlzKGNvbmZpZy5maWx0ZXJzKS5sZW5ndGggLSAxKSB7XG4gICAgICAgICAgICAgICAgZmlsdGVyVGl0bGUgPSBmaWx0ZXJUaXRsZS5jb25jYXQoJyB8ICcpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGluZGV4Kys7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgICB0ZXh0OiBmaWx0ZXJUaXRsZSxcbiAgICAgICAgICAgICAgc3R5bGU6ICdoNCcsXG4gICAgICAgICAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDEwXSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgbGV0IGlkeCA9IDA7XG4gICAgICAgICAgICBzZWN0aW9uLnRhYnMgPSBbXTtcbiAgICAgICAgICAgIGZvciAobGV0IF9kIG9mIE9iamVjdC5rZXlzKGNvbmZpZy5jb25maWcpKSB7XG4gICAgICAgICAgICAgIGZvciAobGV0IGMgb2YgQWdlbnRDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChsZXQgcyBvZiBjLnNlY3Rpb25zKSB7XG4gICAgICAgICAgICAgICAgICBzZWN0aW9uLm9wdHMgPSBzLm9wdHMgfHwge307XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCBjbiBvZiBzLmNvbmZpZyB8fCBbXSkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoY24uY29uZmlndXJhdGlvbiA9PT0gX2QpIHtcbiAgICAgICAgICAgICAgICAgICAgICBzZWN0aW9uLmxhYmVscyA9IHMubGFiZWxzIHx8IFtbXV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIGZvciAobGV0IHdvIG9mIHMud29kbGUgfHwgW10pIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHdvLm5hbWUgPT09IF9kKSB7XG4gICAgICAgICAgICAgICAgICAgICAgc2VjdGlvbi5sYWJlbHMgPSBzLmxhYmVscyB8fCBbW11dO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIHNlY3Rpb24ubGFiZWxzWzBdWydwYWNrJ10gPSAnUGFja3MnO1xuICAgICAgICAgICAgICBzZWN0aW9uLmxhYmVsc1swXVsnY29udGVudCddID0gJ0V2YWx1YXRpb25zJztcbiAgICAgICAgICAgICAgc2VjdGlvbi5sYWJlbHNbMF1bJzcnXSA9ICdTY2FuIGxpc3RlbmluZyBuZXR3b3RrIHBvcnRzJztcbiAgICAgICAgICAgICAgc2VjdGlvbi50YWJzLnB1c2goZXF1aXZhbGVuY2VzW19kXSk7XG5cbiAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoY29uZmlnLmNvbmZpZ1tfZF0pKSB7XG4gICAgICAgICAgICAgICAgLyogTE9HIENPTExFQ1RPUiAqL1xuICAgICAgICAgICAgICAgIGlmIChfZCA9PT0gJ2xvY2FsZmlsZScpIHtcbiAgICAgICAgICAgICAgICAgIGxldCBncm91cHMgPSBbXTtcbiAgICAgICAgICAgICAgICAgIGNvbmZpZy5jb25maWdbX2RdLmZvckVhY2goKG9iaikgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIWdyb3Vwc1tvYmoubG9nZm9ybWF0XSkge1xuICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XS5wdXNoKG9iaik7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKGdyb3VwcykuZm9yRWFjaCgoZ3JvdXApID0+IHtcbiAgICAgICAgICAgICAgICAgICAgbGV0IHNhdmVpZHggPSAwO1xuICAgICAgICAgICAgICAgICAgICBncm91cHNbZ3JvdXBdLmZvckVhY2goKHgsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICBpZiAoT2JqZWN0LmtleXMoeCkubGVuZ3RoID4gT2JqZWN0LmtleXMoZ3JvdXBzW2dyb3VwXVtzYXZlaWR4XSkubGVuZ3RoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzYXZlaWR4ID0gaTtcbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBjb2x1bW5zID0gT2JqZWN0LmtleXMoZ3JvdXBzW2dyb3VwXVtzYXZlaWR4XSk7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IHJvd3MgPSBncm91cHNbZ3JvdXBdLm1hcCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIGxldCByb3cgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGtleSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGVvZiB4W2tleV0gIT09ICdvYmplY3QnXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPyB4W2tleV1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IEFycmF5LmlzQXJyYXkoeFtrZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgID8geFtrZXldLm1hcCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4geCArICdcXG4nO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IEpTT04uc3RyaW5naWZ5KHhba2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJvdztcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoY29sLCBpKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgY29sdW1uc1tpXSA9IGNvbFswXS50b1VwcGVyQ2FzZSgpICsgY29sLnNsaWNlKDEpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnTG9jYWwgZmlsZXMnLFxuICAgICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgICAgY29sdW1ucyxcbiAgICAgICAgICAgICAgICAgICAgICByb3dzLFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoX2QgPT09ICdsYWJlbHMnKSB7XG4gICAgICAgICAgICAgICAgICBjb25zdCBvYmogPSBjb25maWcuY29uZmlnW19kXVswXS5sYWJlbDtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGNvbHVtbnMgPSBPYmplY3Qua2V5cyhvYmpbMF0pO1xuICAgICAgICAgICAgICAgICAgaWYgKCFjb2x1bW5zLmluY2x1ZGVzKCdoaWRkZW4nKSkge1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLnB1c2goJ2hpZGRlbicpO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgY29uc3Qgcm93cyA9IG9iai5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGtleSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHhba2V5XSk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gcm93O1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGNvbCwgaSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zW2ldID0gY29sWzBdLnRvVXBwZXJDYXNlKCkgKyBjb2wuc2xpY2UoMSk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU6ICdMYWJlbHMnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLFxuICAgICAgICAgICAgICAgICAgICByb3dzLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgIGZvciAobGV0IF9kMiBvZiBjb25maWcuY29uZmlnW19kXSkge1xuICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCguLi50aGlzLmdldENvbmZpZ1RhYmxlcyhfZDIsIHNlY3Rpb24sIGlkeCkpO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvKklOVEVHUklUWSBNT05JVE9SSU5HIE1PTklUT1JFRCBESVJFQ1RPUklFUyAqL1xuICAgICAgICAgICAgICAgIGlmIChjb25maWcuY29uZmlnW19kXS5kaXJlY3Rvcmllcykge1xuICAgICAgICAgICAgICAgICAgY29uc3QgZGlyZWN0b3JpZXMgPSBjb25maWcuY29uZmlnW19kXS5kaXJlY3RvcmllcztcbiAgICAgICAgICAgICAgICAgIGRlbGV0ZSBjb25maWcuY29uZmlnW19kXS5kaXJlY3RvcmllcztcbiAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKGNvbmZpZy5jb25maWdbX2RdLCBzZWN0aW9uLCBpZHgpKTtcbiAgICAgICAgICAgICAgICAgIGxldCBkaWZmT3B0cyA9IFtdO1xuICAgICAgICAgICAgICAgICAgT2JqZWN0LmtleXMoc2VjdGlvbi5vcHRzKS5mb3JFYWNoKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGRpZmZPcHRzLnB1c2goeCk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGNvbHVtbnMgPSBbXG4gICAgICAgICAgICAgICAgICAgICcnLFxuICAgICAgICAgICAgICAgICAgICAuLi5kaWZmT3B0cy5maWx0ZXIoKHgpID0+IHggIT09ICdjaGVja19hbGwnICYmIHggIT09ICdjaGVja19zdW0nKSxcbiAgICAgICAgICAgICAgICAgIF07XG4gICAgICAgICAgICAgICAgICBsZXQgcm93cyA9IFtdO1xuICAgICAgICAgICAgICAgICAgZGlyZWN0b3JpZXMuZm9yRWFjaCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBsZXQgcm93ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgucGF0aCk7XG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIGlmICh5ICE9PSAnJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgeSA9IHkgIT09ICdjaGVja193aG9kYXRhJyA/IHkgOiAnd2hvZGF0YSc7XG4gICAgICAgICAgICAgICAgICAgICAgICByb3cucHVzaCh4W3ldID8geFt5XSA6ICdubycpO1xuICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgucmVjdXJzaW9uX2xldmVsKTtcbiAgICAgICAgICAgICAgICAgICAgcm93cy5wdXNoKHJvdyk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeCwgaWR4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnNbaWR4XSA9IHNlY3Rpb24ub3B0c1t4XTtcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKCdSTCcpO1xuICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ01vbml0b3JlZCBkaXJlY3RvcmllcycsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgIHJvd3MsXG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goLi4udGhpcy5nZXRDb25maWdUYWJsZXMoY29uZmlnLmNvbmZpZ1tfZF0sIHNlY3Rpb24sIGlkeCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBmb3IgKGNvbnN0IHRhYmxlIG9mIHRhYmxlcykge1xuICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29uZmlnVGFibGVzKFt0YWJsZV0pO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlkeCsrO1xuICAgICAgICAgICAgICB0YWJsZXMgPSBbXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRhYmxlcyA9IFtdO1xuICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0EgY29uZmlndXJhdGlvbiBmb3IgdGhpcyBncm91cCBoYXMgbm90IHlldCBiZWVuIHNldCB1cC4nLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDEyLCBjb2xvcjogJyMwMDAnIH0sXG4gICAgICAgICAgICBtYXJnaW46IFswLCAxMCwgMCwgMTVdLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vIEFnZW50cyBpbiBncm91cFxuICAgICAgaWYgKGNvbXBvbmVudHNbJzEnXSkge1xuICAgICAgICBhd2FpdCB0aGlzLnJlbmRlckhlYWRlcihcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIHByaW50ZXIsXG4gICAgICAgICAgJ2dyb3VwQ29uZmlnJyxcbiAgICAgICAgICBncm91cElELFxuICAgICAgICAgIFtdLFxuICAgICAgICAgIGFwaUlkXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHByaW50ZXIucHJpbnQoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMuZmlsZW5hbWV9IHdhcyBjcmVhdGVkYCxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzR3JvdXBzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA1MDI5LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH0sICh7cGFyYW1zOiB7IGdyb3VwSUQgfX0pID0+IGB3YXp1aC1ncm91cC1jb25maWd1cmF0aW9uLSR7Z3JvdXBJRH0tJHt0aGlzLmdlbmVyYXRlUmVwb3J0VGltZXN0YW1wKCl9LnBkZmApXG5cbiAgLyoqXG4gICAqIENyZWF0ZSBhIHJlcG9ydCBmb3IgdGhlIGFnZW50c1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMgeyp9IHJlcG9ydHMgbGlzdCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbiA9IHRoaXMuY2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvciggYXN5bmMgKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsXG4gICAgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5XG4gICkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbicsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IGNvbXBvbmVudHMsIGFwaUlkIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICBjb25zdCB7IGFnZW50SUQgfSA9IHJlcXVlc3QucGFyYW1zO1xuXG4gICAgICBjb25zdCBwcmludGVyID0gbmV3IFJlcG9ydFByaW50ZXIoKTtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLmhhc2hVc2VybmFtZSkpO1xuXG4gICAgICBsZXQgd21vZHVsZXNSZXNwb25zZSA9IHt9O1xuICAgICAgbGV0IHRhYmxlcyA9IFtdO1xuICAgICAgdHJ5IHtcbiAgICAgICAgd21vZHVsZXNSZXNwb25zZSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9hZ2VudHMvJHthZ2VudElEfS9jb25maWcvd21vZHVsZXMvd21vZHVsZXNgLFxuICAgICAgICAgIHt9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpyZXBvcnQnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAnZGVidWcnKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgdGhpcy5yZW5kZXJIZWFkZXIoY29udGV4dCwgcHJpbnRlciwgJ2FnZW50Q29uZmlnJywgJ2FnZW50Q29uZmlnJywgYWdlbnRJRCwgYXBpSWQpO1xuXG4gICAgICBsZXQgaWR4Q29tcG9uZW50ID0gMDtcbiAgICAgIGZvciAobGV0IGNvbmZpZyBvZiBBZ2VudENvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMpIHtcbiAgICAgICAgbGV0IHRpdGxlT2ZTZWN0aW9uID0gZmFsc2U7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNDb25maWd1cmF0aW9uJyxcbiAgICAgICAgICBgSXRlcmF0ZSBvdmVyICR7Y29uZmlnLnNlY3Rpb25zLmxlbmd0aH0gY29uZmlndXJhdGlvbiBzZWN0aW9uc2AsXG4gICAgICAgICAgJ2RlYnVnJ1xuICAgICAgICApO1xuICAgICAgICBmb3IgKGxldCBzZWN0aW9uIG9mIGNvbmZpZy5zZWN0aW9ucykge1xuICAgICAgICAgIGxldCB0aXRsZU9mU3Vic2VjdGlvbiA9IGZhbHNlO1xuICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIGNvbXBvbmVudHNbaWR4Q29tcG9uZW50XSAmJlxuICAgICAgICAgICAgKHNlY3Rpb24uY29uZmlnIHx8IHNlY3Rpb24ud29kbGUpXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICBsZXQgaWR4ID0gMDtcbiAgICAgICAgICAgIGNvbnN0IGNvbmZpZ3MgPSAoc2VjdGlvbi5jb25maWcgfHwgW10pLmNvbmNhdChzZWN0aW9uLndvZGxlIHx8IFtdKTtcbiAgICAgICAgICAgIGxvZyhcbiAgICAgICAgICAgICAgJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbicsXG4gICAgICAgICAgICAgIGBJdGVyYXRlIG92ZXIgJHtjb25maWdzLmxlbmd0aH0gY29uZmlndXJhdGlvbiBibG9ja3NgLFxuICAgICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgZm9yIChsZXQgY29uZiBvZiBjb25maWdzKSB7XG4gICAgICAgICAgICAgIGxldCBhZ2VudENvbmZpZ1Jlc3BvbnNlID0ge307XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKCFjb25mWyduYW1lJ10pIHtcbiAgICAgICAgICAgICAgICAgIGFnZW50Q29uZmlnUmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgICAgICAgICAgYC9hZ2VudHMvJHthZ2VudElEfS9jb25maWcvJHtjb25mLmNvbXBvbmVudH0vJHtjb25mLmNvbmZpZ3VyYXRpb259YCxcbiAgICAgICAgICAgICAgICAgICAge30sXG4gICAgICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCB3b2RsZSBvZiB3bW9kdWxlc1Jlc3BvbnNlLmRhdGEuZGF0YVsnd21vZHVsZXMnXSkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoT2JqZWN0LmtleXMod29kbGUpWzBdID09PSBjb25mWyduYW1lJ10pIHtcbiAgICAgICAgICAgICAgICAgICAgICBhZ2VudENvbmZpZ1Jlc3BvbnNlLmRhdGEgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBkYXRhOiB3b2RsZSxcbiAgICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgY29uc3QgYWdlbnRDb25maWcgPVxuICAgICAgICAgICAgICAgICAgYWdlbnRDb25maWdSZXNwb25zZSAmJiBhZ2VudENvbmZpZ1Jlc3BvbnNlLmRhdGEgJiYgYWdlbnRDb25maWdSZXNwb25zZS5kYXRhLmRhdGE7XG4gICAgICAgICAgICAgICAgaWYgKCF0aXRsZU9mU2VjdGlvbikge1xuICAgICAgICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgICAgICAgICAgdGV4dDogY29uZmlnLnRpdGxlLFxuICAgICAgICAgICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbMCwgMCwgMCwgMTVdLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICB0aXRsZU9mU2VjdGlvbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghdGl0bGVPZlN1YnNlY3Rpb24pIHtcbiAgICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgICAgICAgIHRleHQ6IHNlY3Rpb24uc3VidGl0bGUsXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlOiAnaDQnLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgICAgICAgICB0ZXh0OiBzZWN0aW9uLmRlc2MsXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxMiwgY29sb3I6ICcjMDAwJyB9LFxuICAgICAgICAgICAgICAgICAgICBtYXJnaW46IFswLCAwLCAwLCAxMF0sXG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIHRpdGxlT2ZTdWJzZWN0aW9uID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKGFnZW50Q29uZmlnKSB7XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCBhZ2VudENvbmZpZ0tleSBvZiBPYmplY3Qua2V5cyhhZ2VudENvbmZpZykpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldKSkge1xuICAgICAgICAgICAgICAgICAgICAgIC8qIExPRyBDT0xMRUNUT1IgKi9cbiAgICAgICAgICAgICAgICAgICAgICBpZiAoY29uZi5maWx0ZXJCeSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgbGV0IGdyb3VwcyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldLmZvckVhY2goKG9iaikgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWdyb3Vwc1tvYmoubG9nZm9ybWF0XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XS5wdXNoKG9iaik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKGdyb3VwcykuZm9yRWFjaCgoZ3JvdXApID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgbGV0IHNhdmVpZHggPSAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgICBncm91cHNbZ3JvdXBdLmZvckVhY2goKHgsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICBPYmplY3Qua2V5cyh4KS5sZW5ndGggPiBPYmplY3Qua2V5cyhncm91cHNbZ3JvdXBdW3NhdmVpZHhdKS5sZW5ndGhcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNhdmVpZHggPSBpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGNvbHVtbnMgPSBPYmplY3Qua2V5cyhncm91cHNbZ3JvdXBdW3NhdmVpZHhdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3Qgcm93cyA9IGdyb3Vwc1tncm91cF0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoa2V5KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb3cucHVzaChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHlwZW9mIHhba2V5XSAhPT0gJ29iamVjdCdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IHhba2V5XVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogQXJyYXkuaXNBcnJheSh4W2tleV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyB4W2tleV0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB4ICsgJ1xcbic7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogSlNPTi5zdHJpbmdpZnkoeFtrZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcm93O1xuICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKChjb2wsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zW2ldID0gY29sWzBdLnRvVXBwZXJDYXNlKCkgKyBjb2wuc2xpY2UoMSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGl0bGU6IHNlY3Rpb24ubGFiZWxzWzBdW2dyb3VwXSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcm93cyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGFnZW50Q29uZmlnS2V5LmNvbmZpZ3VyYXRpb24gIT09ICdzb2NrZXQnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgLi4udGhpcy5nZXRDb25maWdUYWJsZXMoYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldLCBzZWN0aW9uLCBpZHgpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBfZDIgb2YgYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKF9kMiwgc2VjdGlvbiwgaWR4KSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgIC8qSU5URUdSSVRZIE1PTklUT1JJTkcgTU9OSVRPUkVEIERJUkVDVE9SSUVTICovXG4gICAgICAgICAgICAgICAgICAgICAgaWYgKGNvbmYubWF0cml4KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zdCB7ZGlyZWN0b3JpZXMsZGlmZixzeW5jaHJvbml6YXRpb24sZmlsZV9saW1pdCwuLi5yZXN0fSA9IGFnZW50Q29uZmlnW2FnZW50Q29uZmlnS2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi50aGlzLmdldENvbmZpZ1RhYmxlcyhyZXN0LCBzZWN0aW9uLCBpZHgpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi4oZGlmZiAmJiBkaWZmLmRpc2tfcXVvdGEgPyB0aGlzLmdldENvbmZpZ1RhYmxlcyhkaWZmLmRpc2tfcXVvdGEsIHt0YWJzOlsnRGlzayBxdW90YSddfSwgMCApOiBbXSksXG4gICAgICAgICAgICAgICAgICAgICAgICAgIC4uLihkaWZmICYmIGRpZmYuZmlsZV9zaXplID8gdGhpcy5nZXRDb25maWdUYWJsZXMoZGlmZi5maWxlX3NpemUsIHt0YWJzOlsnRmlsZSBzaXplJ119LCAwICk6IFtdKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uKHN5bmNocm9uaXphdGlvbiA/IHRoaXMuZ2V0Q29uZmlnVGFibGVzKHN5bmNocm9uaXphdGlvbiwge3RhYnM6WydTeW5jaHJvbml6YXRpb24nXX0sIDAgKTogW10pLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi4oZmlsZV9saW1pdCA/IHRoaXMuZ2V0Q29uZmlnVGFibGVzKGZpbGVfbGltaXQsIHt0YWJzOlsnRmlsZSBsaW1pdCddfSwgMCApOiBbXSksXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgbGV0IGRpZmZPcHRzID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBPYmplY3Qua2V5cyhzZWN0aW9uLm9wdHMpLmZvckVhY2goKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgZGlmZk9wdHMucHVzaCh4KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgY29sdW1ucyA9IFtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgJycsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIC4uLmRpZmZPcHRzLmZpbHRlcigoeCkgPT4geCAhPT0gJ2NoZWNrX2FsbCcgJiYgeCAhPT0gJ2NoZWNrX3N1bScpLFxuICAgICAgICAgICAgICAgICAgICAgICAgXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxldCByb3dzID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBkaXJlY3Rvcmllcy5mb3JFYWNoKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGxldCByb3cgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goeC5kaXIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKHkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoeSAhPT0gJycpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgub3B0cy5pbmRleE9mKHkpID4gLTEgPyAneWVzJyA6ICdubycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgucmVjdXJzaW9uX2xldmVsKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgcm93cy5wdXNoKHJvdyk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeCwgaWR4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnNbaWR4XSA9IHNlY3Rpb24ub3B0c1t4XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKCdSTCcpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ01vbml0b3JlZCBkaXJlY3RvcmllcycsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHJvd3MsXG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goXG4gICAgICAgICAgICAgICAgICAgICAgICAgIC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKGFnZW50Q29uZmlnW2FnZW50Q29uZmlnS2V5XSwgc2VjdGlvbiwgaWR4KVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgLy8gUHJpbnQgbm8gY29uZmlndXJlZCBtb2R1bGUgYW5kIGxpbmsgdG8gdGhlIGRvY3VtZW50YXRpb25cbiAgICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgICAgICAgIHRleHQ6IFtcbiAgICAgICAgICAgICAgICAgICAgICAnVGhpcyBtb2R1bGUgaXMgbm90IGNvbmZpZ3VyZWQuIFBsZWFzZSB0YWtlIGEgbG9vayBvbiBob3cgdG8gY29uZmlndXJlIGl0IGluICcsXG4gICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogYCR7c2VjdGlvbi5zdWJ0aXRsZS50b0xvd2VyQ2FzZSgpfSBjb25maWd1cmF0aW9uLmAsXG4gICAgICAgICAgICAgICAgICAgICAgICBsaW5rOiBzZWN0aW9uLmRvY3VMaW5rLFxuICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDEyLCBjb2xvcjogJyMxYTBkYWInIH0sXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbMCwgMCwgMCwgMjBdLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgICAgIGxvZygncmVwb3J0aW5nOnJlcG9ydCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsICdkZWJ1ZycpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlkeCsrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZm9yIChjb25zdCB0YWJsZSBvZiB0YWJsZXMpIHtcbiAgICAgICAgICAgICAgcHJpbnRlci5hZGRDb25maWdUYWJsZXMoW3RhYmxlXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIGlkeENvbXBvbmVudCsrO1xuICAgICAgICAgIHRhYmxlcyA9IFtdO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHByaW50ZXIucHJpbnQoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMuZmlsZW5hbWV9IHdhcyBjcmVhdGVkYCxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAyOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9LCAoeyBwYXJhbXM6IHsgYWdlbnRJRCB9fSkgPT4gYHdhenVoLWFnZW50LWNvbmZpZ3VyYXRpb24tJHthZ2VudElEfS0ke3RoaXMuZ2VuZXJhdGVSZXBvcnRUaW1lc3RhbXAoKX0ucGRmYClcblxuICAvKipcbiAgICogQ3JlYXRlIGEgcmVwb3J0IGZvciB0aGUgYWdlbnRzXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7Kn0gcmVwb3J0cyBsaXN0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnkgPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoIGFzeW5jIChcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeVxuICApID0+IHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50c0ludmVudG9yeScsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IHNlYXJjaEJhciwgZmlsdGVycywgdGltZSwgaW5kZXhQYXR0ZXJuVGl0bGUsIGFwaUlkIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICBjb25zdCB7IGFnZW50SUQgfSA9IHJlcXVlc3QucGFyYW1zO1xuICAgICAgY29uc3QgeyBmcm9tLCB0byB9ID0gdGltZSB8fCB7fTtcbiAgICAgIC8vIEluaXRcbiAgICAgIGNvbnN0IHByaW50ZXIgPSBuZXcgUmVwb3J0UHJpbnRlcigpO1xuXG4gICAgICBjb25zdCB7IGhhc2hVc2VybmFtZSB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5zZWN1cml0eS5nZXRDdXJyZW50VXNlcihyZXF1ZXN0LCBjb250ZXh0KTtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgaGFzaFVzZXJuYW1lKSk7XG5cbiAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnknLCBgU3lzY29sbGVjdG9yIHJlcG9ydGAsICdkZWJ1ZycpO1xuICAgICAgY29uc3QgW3Nhbml0aXplZEZpbHRlcnMsIGFnZW50c0ZpbHRlcl0gPSBmaWx0ZXJzID8gdGhpcy5zYW5pdGl6ZUtpYmFuYUZpbHRlcnMoZmlsdGVycywgc2VhcmNoQmFyKSA6IFtmYWxzZSwgbnVsbF07XG5cbiAgICAgIC8vIEdldCB0aGUgYWdlbnQgT1NcbiAgICAgIGxldCBhZ2VudE9zID0gJyc7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBhZ2VudFJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAnL2FnZW50cycsXG4gICAgICAgICAgeyBwYXJhbXM6IHsgcTogYGlkPSR7YWdlbnRJRH1gIH0gfSxcbiAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICApO1xuICAgICAgICBhZ2VudE9zID0gYWdlbnRSZXNwb25zZS5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNbMF0ub3MucGxhdGZvcm07XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzSW52ZW50b3J5JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgJ2RlYnVnJyk7XG4gICAgICB9XG5cbiAgICAgIC8vIEFkZCB0aXRsZVxuICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICB0ZXh0OiAnSW52ZW50b3J5IGRhdGEgcmVwb3J0JyxcbiAgICAgICAgc3R5bGU6ICdoMScsXG4gICAgICB9KTtcblxuICAgICAgLy8gQWRkIHRhYmxlIHdpdGggdGhlIGFnZW50IGluZm9cbiAgICAgIGF3YWl0IGJ1aWxkQWdlbnRzVGFibGUoY29udGV4dCwgcHJpbnRlciwgW2FnZW50SURdLCBhcGlJZCk7XG5cbiAgICAgIC8vIEdldCBzeXNjb2xsZWN0b3IgcGFja2FnZXMgYW5kIHByb2Nlc3Nlc1xuICAgICAgY29uc3QgYWdlbnRSZXF1ZXN0c0ludmVudG9yeSA9IFtcbiAgICAgICAge1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50SUR9L3BhY2thZ2VzYCxcbiAgICAgICAgICBsb2dnZXJNZXNzYWdlOiBgRmV0Y2hpbmcgcGFja2FnZXMgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ1BhY2thZ2VzJyxcbiAgICAgICAgICAgIGNvbHVtbnM6XG4gICAgICAgICAgICAgIGFnZW50T3MgPT09ICd3aW5kb3dzJ1xuICAgICAgICAgICAgICAgID8gW1xuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnTmFtZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2FyY2hpdGVjdHVyZScsIGxhYmVsOiAnQXJjaGl0ZWN0dXJlJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAndmVyc2lvbicsIGxhYmVsOiAnVmVyc2lvbicgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3ZlbmRvcicsIGxhYmVsOiAnVmVuZG9yJyB9LFxuICAgICAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgICAgIDogW1xuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnTmFtZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2FyY2hpdGVjdHVyZScsIGxhYmVsOiAnQXJjaGl0ZWN0dXJlJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAndmVyc2lvbicsIGxhYmVsOiAnVmVyc2lvbicgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3ZlbmRvcicsIGxhYmVsOiAnVmVuZG9yJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnZGVzY3JpcHRpb24nLCBsYWJlbDogJ0Rlc2NyaXB0aW9uJyB9LFxuICAgICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgZW5kcG9pbnQ6IGAvc3lzY29sbGVjdG9yLyR7YWdlbnRJRH0vcHJvY2Vzc2VzYCxcbiAgICAgICAgICBsb2dnZXJNZXNzYWdlOiBgRmV0Y2hpbmcgcHJvY2Vzc2VzIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdQcm9jZXNzZXMnLFxuICAgICAgICAgICAgY29sdW1uczpcbiAgICAgICAgICAgICAgYWdlbnRPcyA9PT0gJ3dpbmRvd3MnXG4gICAgICAgICAgICAgICAgPyBbXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdOYW1lJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnY21kJywgbGFiZWw6ICdDTUQnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdwcmlvcml0eScsIGxhYmVsOiAnUHJpb3JpdHknIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdubHdwJywgbGFiZWw6ICdOTFdQJyB9LFxuICAgICAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgICAgIDogW1xuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnTmFtZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2V1c2VyJywgbGFiZWw6ICdFZmZlY3RpdmUgdXNlcicgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ25pY2UnLCBsYWJlbDogJ1ByaW9yaXR5JyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnc3RhdGUnLCBsYWJlbDogJ1N0YXRlJyB9LFxuICAgICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIG1hcFJlc3BvbnNlSXRlbXM6IChpdGVtKSA9PlxuICAgICAgICAgICAgYWdlbnRPcyA9PT0gJ3dpbmRvd3MnID8gaXRlbSA6IHsgLi4uaXRlbSwgc3RhdGU6IFByb2Nlc3NFcXVpdmFsZW5jZVtpdGVtLnN0YXRlXSB9LFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgZW5kcG9pbnQ6IGAvc3lzY29sbGVjdG9yLyR7YWdlbnRJRH0vcG9ydHNgLFxuICAgICAgICAgIGxvZ2dlck1lc3NhZ2U6IGBGZXRjaGluZyBwb3J0cyBmb3IgYWdlbnQgJHthZ2VudElEfWAsXG4gICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgIHRpdGxlOiAnTmV0d29yayBwb3J0cycsXG4gICAgICAgICAgICBjb2x1bW5zOlxuICAgICAgICAgICAgICBhZ2VudE9zID09PSAnd2luZG93cydcbiAgICAgICAgICAgICAgICA/IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2xvY2FsX2lwJywgbGFiZWw6ICdMb2NhbCBJUCBhZGRyZXNzJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbG9jYWxfcG9ydCcsIGxhYmVsOiAnTG9jYWwgcG9ydCcgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3Byb2Nlc3MnLCBsYWJlbDogJ1Byb2Nlc3MnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdzdGF0ZScsIGxhYmVsOiAnU3RhdGUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdwcm90b2NvbCcsIGxhYmVsOiAnUHJvdG9jb2wnIH0sXG4gICAgICAgICAgICAgICAgICBdXG4gICAgICAgICAgICAgICAgOiBbXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdsb2NhbF9pcCcsIGxhYmVsOiAnTG9jYWwgSVAgYWRkcmVzcycgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2xvY2FsX3BvcnQnLCBsYWJlbDogJ0xvY2FsIHBvcnQnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdzdGF0ZScsIGxhYmVsOiAnU3RhdGUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdwcm90b2NvbCcsIGxhYmVsOiAnUHJvdG9jb2wnIH0sXG4gICAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgbWFwUmVzcG9uc2VJdGVtczogKGl0ZW0pID0+ICh7XG4gICAgICAgICAgICAuLi5pdGVtLFxuICAgICAgICAgICAgbG9jYWxfaXA6IGl0ZW0ubG9jYWwuaXAsXG4gICAgICAgICAgICBsb2NhbF9wb3J0OiBpdGVtLmxvY2FsLnBvcnQsXG4gICAgICAgICAgfSksXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9uZXRpZmFjZWAsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIG5ldGlmYWNlIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdOZXR3b3JrIGludGVyZmFjZXMnLFxuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAnbmFtZScsIGxhYmVsOiAnTmFtZScgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ21hYycsIGxhYmVsOiAnTWFjJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnc3RhdGUnLCBsYWJlbDogJ1N0YXRlJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnbXR1JywgbGFiZWw6ICdNVFUnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICd0eXBlJywgbGFiZWw6ICdUeXBlJyB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgZW5kcG9pbnQ6IGAvc3lzY29sbGVjdG9yLyR7YWdlbnRJRH0vbmV0YWRkcmAsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIG5ldGFkZHIgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ05ldHdvcmsgc2V0dGluZ3MnLFxuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAnaWZhY2UnLCBsYWJlbDogJ0ludGVyZmFjZScgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ2FkZHJlc3MnLCBsYWJlbDogJ0FkZHJlc3MnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICduZXRtYXNrJywgbGFiZWw6ICdOZXRtYXNrJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAncHJvdG8nLCBsYWJlbDogJ1Byb3RvY29sJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnYnJvYWRjYXN0JywgbGFiZWw6ICdCcm9hZGNhc3QnIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICBdO1xuXG4gICAgICBhZ2VudE9zID09PSAnd2luZG93cycgJiZcbiAgICAgICAgYWdlbnRSZXF1ZXN0c0ludmVudG9yeS5wdXNoKHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9ob3RmaXhlc2AsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIGhvdGZpeGVzIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdXaW5kb3dzIHVwZGF0ZXMnLFxuICAgICAgICAgICAgY29sdW1uczogW3sgaWQ6ICdob3RmaXgnLCBsYWJlbDogJ1VwZGF0ZSBjb2RlJyB9XSxcbiAgICAgICAgICB9LFxuICAgICAgICB9KTtcblxuICAgICAgY29uc3QgcmVxdWVzdEludmVudG9yeSA9IGFzeW5jIChhZ2VudFJlcXVlc3RJbnZlbnRvcnkpID0+IHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBsb2coXG4gICAgICAgICAgICAncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnknLFxuICAgICAgICAgICAgYWdlbnRSZXF1ZXN0SW52ZW50b3J5LmxvZ2dlck1lc3NhZ2UsXG4gICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgKTtcblxuICAgICAgICAgIGNvbnN0IGludmVudG9yeVJlc3BvbnNlID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICAgYWdlbnRSZXF1ZXN0SW52ZW50b3J5LmVuZHBvaW50LFxuICAgICAgICAgICAge30sXG4gICAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICAgICk7XG5cbiAgICAgICAgICBjb25zdCBpbnZlbnRvcnkgPVxuICAgICAgICAgICAgaW52ZW50b3J5UmVzcG9uc2UgJiZcbiAgICAgICAgICAgIGludmVudG9yeVJlc3BvbnNlLmRhdGEgJiZcbiAgICAgICAgICAgIGludmVudG9yeVJlc3BvbnNlLmRhdGEuZGF0YSAmJlxuICAgICAgICAgICAgaW52ZW50b3J5UmVzcG9uc2UuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zO1xuICAgICAgICAgIGlmIChpbnZlbnRvcnkpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgIC4uLmFnZW50UmVxdWVzdEludmVudG9yeS50YWJsZSxcbiAgICAgICAgICAgICAgaXRlbXM6IGFnZW50UmVxdWVzdEludmVudG9yeS5tYXBSZXNwb25zZUl0ZW1zXG4gICAgICAgICAgICAgICAgPyBpbnZlbnRvcnkubWFwKGFnZW50UmVxdWVzdEludmVudG9yeS5tYXBSZXNwb25zZUl0ZW1zKVxuICAgICAgICAgICAgICAgIDogaW52ZW50b3J5LFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50c0ludmVudG9yeScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsICdkZWJ1ZycpO1xuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICBpZiAodGltZSkge1xuICAgICAgICBhd2FpdCBleHRlbmRlZEluZm9ybWF0aW9uKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgcHJpbnRlcixcbiAgICAgICAgICAnYWdlbnRzJyxcbiAgICAgICAgICAnc3lzY29sbGVjdG9yJyxcbiAgICAgICAgICBhcGlJZCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIHNhbml0aXplZEZpbHRlcnMgKyAnIEFORCBydWxlLmdyb3VwczogXCJ2dWxuZXJhYmlsaXR5LWRldGVjdG9yXCInLFxuICAgICAgICAgIGFnZW50c0ZpbHRlcixcbiAgICAgICAgICBpbmRleFBhdHRlcm5UaXRsZSxcbiAgICAgICAgICBhZ2VudElEXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIC8vIEFkZCBpbnZlbnRvcnkgdGFibGVzXG4gICAgICAoYXdhaXQgUHJvbWlzZS5hbGwoYWdlbnRSZXF1ZXN0c0ludmVudG9yeS5tYXAocmVxdWVzdEludmVudG9yeSkpKVxuICAgICAgICAuZmlsdGVyKCh0YWJsZSkgPT4gdGFibGUpXG4gICAgICAgIC5mb3JFYWNoKCh0YWJsZSkgPT4gcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh0YWJsZSkpO1xuXG4gICAgICAvLyBQcmludCB0aGUgZG9jdW1lbnRcbiAgICAgIGF3YWl0IHByaW50ZXIucHJpbnQoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMuZmlsZW5hbWV9IHdhcyBjcmVhdGVkYCxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA1MDI5LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH0sICh7cGFyYW1zOiB7IGFnZW50SUQgfX0pID0+IGB3YXp1aC1hZ2VudC1pbnZlbnRvcnktJHthZ2VudElEfS0ke3RoaXMuZ2VuZXJhdGVSZXBvcnRUaW1lc3RhbXAoKX0ucGRmYClcblxuICAvKipcbiAgICogRmV0Y2ggdGhlIHJlcG9ydHMgbGlzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge0FycmF5PE9iamVjdD59IHJlcG9ydHMgbGlzdCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBnZXRSZXBvcnRzKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsXG4gICAgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5XG4gICkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRzJywgYEZldGNoaW5nIGNyZWF0ZWQgcmVwb3J0c2AsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IGhhc2hVc2VybmFtZSB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5zZWN1cml0eS5nZXRDdXJyZW50VXNlcihyZXF1ZXN0LCBjb250ZXh0KTtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjb25zdCB1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGggPSBwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgaGFzaFVzZXJuYW1lKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKHVzZXJSZXBvcnRzRGlyZWN0b3J5UGF0aCk7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRzJywgYERpcmVjdG9yeTogJHt1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGh9YCwgJ2RlYnVnJyk7XG5cbiAgICAgIGNvbnN0IHNvcnRSZXBvcnRzQnlEYXRlID0gKGEsIGIpID0+IChhLmRhdGUgPCBiLmRhdGUgPyAxIDogYS5kYXRlID4gYi5kYXRlID8gLTEgOiAwKTtcblxuICAgICAgY29uc3QgcmVwb3J0cyA9IGZzLnJlYWRkaXJTeW5jKHVzZXJSZXBvcnRzRGlyZWN0b3J5UGF0aCkubWFwKChmaWxlKSA9PiB7XG4gICAgICAgIGNvbnN0IHN0YXRzID0gZnMuc3RhdFN5bmModXNlclJlcG9ydHNEaXJlY3RvcnlQYXRoICsgJy8nICsgZmlsZSk7XG4gICAgICAgIC8vIEdldCB0aGUgZmlsZSBjcmVhdGlvbiB0aW1lIChiaXRodGltZSkuIEl0IHJldHVybnMgdGhlIGZpcnN0IHZhbHVlIHRoYXQgaXMgYSB0cnV0aHkgdmFsdWUgb2YgbmV4dCBmaWxlIHN0YXRzOiBiaXJ0aHRpbWUsIG10aW1lLCBjdGltZSBhbmQgYXRpbWUuXG4gICAgICAgIC8vIFRoaXMgc29sdmVzIHNvbWUgT1NzIGNhbiBoYXZlIHRoZSBiaXRodGltZU1zIGVxdWFsIHRvIDAgYW5kIHJldHVybnMgdGhlIGRhdGUgbGlrZSAxOTcwLTAxLTAxXG4gICAgICAgIGNvbnN0IGJpcnRoVGltZUZpZWxkID0gWydiaXJ0aHRpbWUnLCAnbXRpbWUnLCAnY3RpbWUnLCAnYXRpbWUnXS5maW5kKFxuICAgICAgICAgICh0aW1lKSA9PiBzdGF0c1tgJHt0aW1lfU1zYF1cbiAgICAgICAgKTtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBuYW1lOiBmaWxlLFxuICAgICAgICAgIHNpemU6IHN0YXRzLnNpemUsXG4gICAgICAgICAgZGF0ZTogc3RhdHNbYmlydGhUaW1lRmllbGRdLFxuICAgICAgICB9O1xuICAgICAgfSk7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRzJywgYFVzaW5nIFRpbVNvcnQgZm9yIHNvcnRpbmcgJHtyZXBvcnRzLmxlbmd0aH0gaXRlbXNgLCAnZGVidWcnKTtcbiAgICAgIFRpbVNvcnQuc29ydChyZXBvcnRzLCBzb3J0UmVwb3J0c0J5RGF0ZSk7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRzJywgYFRvdGFsIHJlcG9ydHM6ICR7cmVwb3J0cy5sZW5ndGh9YCwgJ2RlYnVnJyk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IHJlcG9ydHMgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpnZXRSZXBvcnRzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA1MDMxLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogRmV0Y2ggc3BlY2lmaWMgcmVwb3J0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSByZXBvcnQgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgZ2V0UmVwb3J0QnlOYW1lID0gdGhpcy5jaGVja1JlcG9ydHNVc2VyRGlyZWN0b3J5SXNWYWxpZFJvdXRlRGVjb3JhdG9yKGFzeW5jIChcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeVxuICApID0+IHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0QnlOYW1lJywgYEdldHRpbmcgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lfSByZXBvcnRgLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHJlcG9ydEZpbGVCdWZmZXIgPSBmcy5yZWFkRmlsZVN5bmMoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vcGRmJyB9LFxuICAgICAgICBib2R5OiByZXBvcnRGaWxlQnVmZmVyLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmdldFJlcG9ydEJ5TmFtZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAzMCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9LCAocmVxdWVzdCkgPT4gcmVxdWVzdC5wYXJhbXMubmFtZSlcblxuICAvKipcbiAgICogRGVsZXRlIHNwZWNpZmljIHJlcG9ydFxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gc3RhdHVzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBkZWxldGVSZXBvcnRCeU5hbWUgPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoYXN5bmMgKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsXG4gICAgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5XG4gICkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpkZWxldGVSZXBvcnRCeU5hbWUnLCBgRGVsZXRpbmcgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lfSByZXBvcnRgLCAnZGVidWcnKTtcbiAgICAgIGZzLnVubGlua1N5bmMoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG4gICAgICBsb2coJ3JlcG9ydGluZzpkZWxldGVSZXBvcnRCeU5hbWUnLCBgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lfSByZXBvcnQgd2FzIGRlbGV0ZWRgLCAnaW5mbycpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogeyBlcnJvcjogMCB9LFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmRlbGV0ZVJlcG9ydEJ5TmFtZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAzMiwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9LChyZXF1ZXN0KSA9PiByZXF1ZXN0LnBhcmFtcy5uYW1lKVxuXG4gIGNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3Iocm91dGVIYW5kbGVyLCByZXBvcnRGaWxlTmFtZUFjY2Vzc29yKXtcbiAgICByZXR1cm4gKGFzeW5jIChcbiAgICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICAgIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCxcbiAgICAgIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeVxuICAgICkgPT4ge1xuICAgICAgdHJ5e1xuICAgICAgICBjb25zdCB7IHVzZXJuYW1lLCBoYXNoVXNlcm5hbWUgfSA9IGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCk7XG4gICAgICAgIGNvbnN0IHVzZXJSZXBvcnRzRGlyZWN0b3J5UGF0aCA9IHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCBoYXNoVXNlcm5hbWUpO1xuICAgICAgICBjb25zdCBmaWxlbmFtZSA9IHJlcG9ydEZpbGVOYW1lQWNjZXNzb3IocmVxdWVzdCk7XG4gICAgICAgIGNvbnN0IHBhdGhGaWxlbmFtZSA9IHBhdGguam9pbih1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGgsIGZpbGVuYW1lKTtcbiAgICAgICAgbG9nKCdyZXBvcnRpbmc6Y2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvcicsIGBDaGVja2luZyB0aGUgdXNlciAke3VzZXJuYW1lfSgke2hhc2hVc2VybmFtZX0pIGNhbiBkbyBhY3Rpb25zIGluIHRoZSByZXBvcnRzIGZpbGU6ICR7cGF0aEZpbGVuYW1lfWAsICdkZWJ1ZycpO1xuICAgICAgICBpZighcGF0aEZpbGVuYW1lLnN0YXJ0c1dpdGgodXNlclJlcG9ydHNEaXJlY3RvcnlQYXRoKSB8fCBwYXRoRmlsZW5hbWUuaW5jbHVkZXMoJy4uLycpKXtcbiAgICAgICAgICBsb2coJ3NlY3VyaXR5OnJlcG9ydGluZzpjaGVja1JlcG9ydHNVc2VyRGlyZWN0b3J5SXNWYWxpZFJvdXRlRGVjb3JhdG9yJywgYFVzZXIgJHt1c2VybmFtZX0oJHtoYXNoVXNlcm5hbWV9KSB0cmllZCB0byBhY2Nlc3MgdG8gYSBub24gdXNlciByZXBvcnQgZmlsZTogJHtwYXRoRmlsZW5hbWV9YCwgJ3dhcm4nKTtcbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuYmFkUmVxdWVzdCh7XG4gICAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICAgIG1lc3NhZ2U6ICc1MDQwIC0gWW91IHNoYWxsIG5vdCBwYXNzISdcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KTtcbiAgICAgICAgfTtcbiAgICAgICAgbG9nKCdyZXBvcnRpbmc6Y2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvcicsICdDaGVja2luZyB0aGUgdXNlciBjYW4gZG8gYWN0aW9ucyBpbiB0aGUgcmVwb3J0cyBmaWxlJywgJ2RlYnVnJyk7XG4gICAgICAgIHJldHVybiBhd2FpdCByb3V0ZUhhbmRsZXIuYmluZCh0aGlzKSh7Li4uY29udGV4dCwgd2F6dWhFbmRwb2ludFBhcmFtczogeyBoYXNoVXNlcm5hbWUsIGZpbGVuYW1lLCBwYXRoRmlsZW5hbWUgfX0sIHJlcXVlc3QsIHJlc3BvbnNlKTtcbiAgICAgIH1jYXRjaChlcnJvcil7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3InLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTA0MCwgNTAwLCByZXNwb25zZSk7XG4gICAgICB9XG4gICAgfSlcbiAgfVxuXG4gIHByaXZhdGUgZ2VuZXJhdGVSZXBvcnRUaW1lc3RhbXAoKXtcbiAgICByZXR1cm4gYCR7KERhdGUubm93KCkgLyAxMDAwKSB8IDB9YDtcbiAgfVxufVxuIl19