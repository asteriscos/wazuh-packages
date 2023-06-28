"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhElasticCtrl = void 0;

var _errorResponse = require("../lib/error-response");

var _logger = require("../lib/logger");

var _getConfiguration = require("../lib/get-configuration");

var _visualizations = require("../integration-files/visualizations");

var _generateAlertsScript = require("../lib/generate-alerts/generate-alerts-script");

var _constants = require("../../common/constants");

var _jwtDecode = _interopRequireDefault(require("jwt-decode"));

var _manageHosts = require("../lib/manage-hosts");

var _cookie = require("../lib/cookie");

var _settings = require("../../common/services/settings");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class WazuhElasticCtrl {
  constructor() {
    _defineProperty(this, "wzSampleAlertsIndexPrefix", void 0);

    _defineProperty(this, "manageHosts", void 0);

    this.wzSampleAlertsIndexPrefix = this.getSampleAlertPrefix();
    this.manageHosts = new _manageHosts.ManageHosts();
  }
  /**
   * This returns the index according the category
   * @param {string} category
   */


  buildSampleIndexByCategory(category) {
    return `${this.wzSampleAlertsIndexPrefix}sample-${category}`;
  }
  /**
   * This returns the defined config for sample alerts prefix or the default value.
   */


  getSampleAlertPrefix() {
    const config = (0, _getConfiguration.getConfiguration)();
    return config['alerts.sample.prefix'] || (0, _settings.getSettingDefaultValue)('alerts.sample.prefix');
  }
  /**
   * This retrieves a template from Elasticsearch
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} template or ErrorResponse
   */


  async getTemplate(context, request, response) {
    try {
      const data = await context.core.opensearch.client.asInternalUser.cat.templates();
      const templates = data.body;

      if (!templates || typeof templates !== 'string') {
        throw new Error('An unknown error occurred when fetching templates from Elasticseach');
      }

      const lastChar = request.params.pattern[request.params.pattern.length - 1]; // Split into separate patterns

      const tmpdata = templates.match(/\[.*\]/g);
      const tmparray = [];

      for (let item of tmpdata) {
        // A template might use more than one pattern
        if (item.includes(',')) {
          item = item.substr(1).slice(0, -1);
          const subItems = item.split(',');

          for (const subitem of subItems) {
            tmparray.push(`[${subitem.trim()}]`);
          }
        } else {
          tmparray.push(item);
        }
      } // Ensure we are handling just patterns


      const array = tmparray.filter(item => item.includes('[') && item.includes(']'));
      const pattern = lastChar === '*' ? request.params.pattern.slice(0, -1) : request.params.pattern;
      const isIncluded = array.filter(item => {
        item = item.slice(1, -1);
        const lastChar = item[item.length - 1];
        item = lastChar === '*' ? item.slice(0, -1) : item;
        return item.includes(pattern) || pattern.includes(item);
      });
      (0, _logger.log)('wazuh-elastic:getTemplate', `Template is valid: ${isIncluded && Array.isArray(isIncluded) && isIncluded.length ? 'yes' : 'no'}`, 'debug');
      return isIncluded && Array.isArray(isIncluded) && isIncluded.length ? response.ok({
        body: {
          statusCode: 200,
          status: true,
          data: `Template found for ${request.params.pattern}`
        }
      }) : response.ok({
        body: {
          statusCode: 200,
          status: false,
          data: `No template found for ${request.params.pattern}`
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getTemplate', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not retrieve templates from Elasticsearch due to ${error.message || error}`, 4002, 500, response);
    }
  }
  /**
   * This check index-pattern
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkPattern(context, request, response) {
    try {
      const data = await context.core.savedObjects.client.find({
        type: 'index-pattern'
      });
      const existsIndexPattern = data.saved_objects.find(item => item.attributes.title === request.params.pattern);
      (0, _logger.log)('wazuh-elastic:checkPattern', `Index pattern found: ${existsIndexPattern ? existsIndexPattern.attributes.title : 'no'}`, 'debug');
      return existsIndexPattern ? response.ok({
        body: {
          statusCode: 200,
          status: true,
          data: 'Index pattern found'
        }
      }) : response.ok({
        body: {
          statusCode: 500,
          status: false,
          error: 10020,
          message: 'Index pattern not found'
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:checkPattern', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Something went wrong retrieving index-patterns from Elasticsearch due to ${error.message || error}`, 4003, 500, response);
    }
  }
  /**
   * This get the fields keys
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<Object>} fields or ErrorResponse
   */


  async getFieldTop(context, request, response) {
    try {
      // Top field payload
      let payload = {
        size: 1,
        query: {
          bool: {
            must: [],
            must_not: {
              term: {
                'agent.id': '000'
              }
            },
            filter: [{
              range: {
                timestamp: {}
              }
            }]
          }
        },
        aggs: {
          '2': {
            terms: {
              field: '',
              size: 1,
              order: {
                _count: 'desc'
              }
            }
          }
        }
      }; // Set up time interval, default to Last 24h

      const timeGTE = 'now-1d';
      const timeLT = 'now';
      payload.query.bool.filter[0].range['timestamp']['gte'] = timeGTE;
      payload.query.bool.filter[0].range['timestamp']['lt'] = timeLT; // Set up match for default cluster name

      payload.query.bool.must.push(request.params.mode === 'cluster' ? {
        match: {
          'cluster.name': request.params.cluster
        }
      } : {
        match: {
          'manager.name': request.params.cluster
        }
      });
      if (request.query.agentsList) payload.query.bool.filter.push({
        terms: {
          'agent.id': request.query.agentsList.split(',')
        }
      });
      payload.aggs['2'].terms.field = request.params.field;
      const data = await context.core.opensearch.client.asCurrentUser.search({
        size: 1,
        index: request.params.pattern,
        body: payload
      });
      return data.body.hits.total.value === 0 || typeof data.body.aggregations['2'].buckets[0] === 'undefined' ? response.ok({
        body: {
          statusCode: 200,
          data: ''
        }
      }) : response.ok({
        body: {
          statusCode: 200,
          data: data.body.aggregations['2'].buckets[0].key
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getFieldTop', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4004, 500, response);
    }
  }
  /**
   * Checks one by one if the requesting user has enough privileges to use
   * an index pattern from the list.
   * @param {Array<Object>} list List of index patterns
   * @param {Object} req
   * @returns {Array<Object>} List of allowed index
   */


  async filterAllowedIndexPatternList(context, list, req) {
    //TODO: review if necesary to delete
    let finalList = [];

    for (let item of list) {
      let results = false,
          forbidden = false;

      try {
        results = await context.core.opensearch.client.asCurrentUser.search({
          index: item.title
        });
      } catch (error) {
        forbidden = true;
      }

      if ((((results || {}).body || {}).hits || {}).total.value >= 1 || !forbidden && (((results || {}).body || {}).hits || {}).total === 0) {
        finalList.push(item);
      }
    }

    return finalList;
  }
  /**
   * Checks for minimum index pattern fields in a list of index patterns.
   * @param {Array<Object>} indexPatternList List of index patterns
   */


  validateIndexPattern(indexPatternList) {
    const minimum = ['timestamp', 'rule.groups', 'manager.name', 'agent.id'];
    let list = [];

    for (const index of indexPatternList) {
      let valid, parsed;

      try {
        parsed = JSON.parse(index.attributes.fields);
      } catch (error) {
        continue;
      }

      valid = parsed.filter(item => minimum.includes(item.name));

      if (valid.length === 4) {
        list.push({
          id: index.id,
          title: index.attributes.title
        });
      }
    }

    return list;
  }
  /**
   * Returns current security platform
   * @param {Object} req
   * @param {Object} reply
   * @returns {String}
   */


  async getCurrentPlatform(context, request, response) {
    try {
      return response.ok({
        body: {
          platform: context.wazuh.security.platform
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getCurrentPlatform', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4011, 500, response);
    }
  }
  /**
   * Replaces visualizations main fields to fit a certain pattern.
   * @param {Array<Object>} app_objects Object containing raw visualizations.
   * @param {String} id Index-pattern id to use in the visualizations. Eg: 'wazuh-alerts'
   */


  async buildVisualizationsRaw(app_objects, id, namespace = false) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      let monitoringPattern = (config || {})['wazuh.monitoring.pattern'] || (0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern');
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', `Building ${app_objects.length} visualizations`, 'debug');
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', `Index pattern ID: ${id}`, 'debug');
      const visArray = [];
      let aux_source, bulk_content;

      for (let element of app_objects) {
        aux_source = JSON.parse(JSON.stringify(element._source)); // Replace index-pattern for visualizations

        if (aux_source && aux_source.kibanaSavedObjectMeta && aux_source.kibanaSavedObjectMeta.searchSourceJSON && typeof aux_source.kibanaSavedObjectMeta.searchSourceJSON === 'string') {
          const defaultStr = aux_source.kibanaSavedObjectMeta.searchSourceJSON;
          const isMonitoring = defaultStr.includes('wazuh-monitoring');

          if (isMonitoring) {
            if (namespace && namespace !== 'default') {
              if (monitoringPattern.includes(namespace) && monitoringPattern.includes('index-pattern:')) {
                monitoringPattern = monitoringPattern.split('index-pattern:')[1];
              }
            }

            aux_source.kibanaSavedObjectMeta.searchSourceJSON = defaultStr.replace(/wazuh-monitoring/g, monitoringPattern[monitoringPattern.length - 1] === '*' || namespace && namespace !== 'default' ? monitoringPattern : monitoringPattern + '*');
          } else {
            aux_source.kibanaSavedObjectMeta.searchSourceJSON = defaultStr.replace(/wazuh-alerts/g, id);
          }
        } // Replace index-pattern for selector visualizations


        if (typeof (aux_source || {}).visState === 'string') {
          aux_source.visState = aux_source.visState.replace(/wazuh-alerts/g, id);
        } // Bulk source


        bulk_content = {};
        bulk_content[element._type] = aux_source;
        visArray.push({
          attributes: bulk_content.visualization,
          type: element._type,
          id: element._id,
          _version: bulk_content.visualization.version
        });
      }

      return visArray;
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Replaces cluster visualizations main fields.
   * @param {Array<Object>} app_objects Object containing raw visualizations.
   * @param {String} id Index-pattern id to use in the visualizations. Eg: 'wazuh-alerts'
   * @param {Array<String>} nodes Array of node names. Eg: ['node01', 'node02']
   * @param {String} name Cluster name. Eg: 'wazuh'
   * @param {String} master_node Master node name. Eg: 'node01'
   */


  buildClusterVisualizationsRaw(app_objects, id, nodes = [], name, master_node, pattern_name = '*') {
    try {
      const visArray = [];
      let aux_source, bulk_content;

      for (const element of app_objects) {
        // Stringify and replace index-pattern for visualizations
        aux_source = JSON.stringify(element._source);
        aux_source = aux_source.replace(/wazuh-alerts/g, id);
        aux_source = JSON.parse(aux_source); // Bulk source

        bulk_content = {};
        bulk_content[element._type] = aux_source;
        const visState = JSON.parse(bulk_content.visualization.visState);
        const title = visState.title;

        if (visState.type && visState.type === 'timelion') {
          let query = '';

          if (title === 'Wazuh App Cluster Overview') {
            for (const node of nodes) {
              query += `.es(index=${pattern_name},q="cluster.name: ${name} AND cluster.node: ${node.name}").label("${node.name}"),`;
            }

            query = query.substring(0, query.length - 1);
          } else if (title === 'Wazuh App Cluster Overview Manager') {
            query += `.es(index=${pattern_name},q="cluster.name: ${name}").label("${name} cluster")`;
          } else {
            if (title.startsWith('Wazuh App Statistics')) {
              const {
                searchSourceJSON
              } = bulk_content.visualization.kibanaSavedObjectMeta;
              bulk_content.visualization.kibanaSavedObjectMeta.searchSourceJSON = searchSourceJSON.replace('wazuh-statistics-*', pattern_name);
            }

            if (title.startsWith('Wazuh App Statistics') && name !== '-' && name !== 'all' && visState.params.expression.includes('q=')) {
              const expressionRegex = /q='\*'/gi;

              const _visState = bulk_content.visualization.visStateByNode ? JSON.parse(bulk_content.visualization.visStateByNode) : visState;

              query += _visState.params.expression.replace(/wazuh-statistics-\*/g, pattern_name).replace(expressionRegex, `q="nodeName.keyword:${name} AND apiName.keyword:${master_node}"`).replace("NODE_NAME", name);
            } else if (title.startsWith('Wazuh App Statistics')) {
              const expressionRegex = /q='\*'/gi;
              query += visState.params.expression.replace(/wazuh-statistics-\*/g, pattern_name).replace(expressionRegex, `q="apiName.keyword:${master_node}"`);
            } else {
              query = visState.params.expression;
            }
          }

          visState.params.expression = query.replace(/'/g, "\"");
          bulk_content.visualization.visState = JSON.stringify(visState);
        }

        visArray.push({
          attributes: bulk_content.visualization,
          type: element._type,
          id: element._id,
          _version: bulk_content.visualization.version
        });
      }

      return visArray;
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:buildClusterVisualizationsRaw', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * This creates a visualization of data in req
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} vis obj or ErrorResponse
   */


  async createVis(context, request, response) {
    try {
      if (!request.params.tab.includes('overview-') && !request.params.tab.includes('agents-')) {
        throw new Error('Missing parameters creating visualizations');
      }

      const tabPrefix = request.params.tab.includes('overview') ? 'overview' : 'agents';
      const tabSplit = request.params.tab.split('-');
      const tabSufix = tabSplit[1];
      const file = tabPrefix === 'overview' ? _visualizations.OverviewVisualizations[tabSufix] : _visualizations.AgentsVisualizations[tabSufix];

      if (!file) {
        return response.notFound({
          body: {
            message: `Visualizations not found for ${request.params.tab}`
          }
        });
      }

      (0, _logger.log)('wazuh-elastic:createVis', `${tabPrefix}[${tabSufix}] with index pattern ${request.params.pattern}`, 'debug');
      const raw = await this.buildVisualizationsRaw(file, request.params.pattern);
      return response.ok({
        body: {
          acknowledge: true,
          raw: raw
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createVis', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4007, 500, response);
    }
  }
  /**
   * This creates a visualization of cluster
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} vis obj or ErrorResponse
   */


  async createClusterVis(context, request, response) {
    try {
      if (!request.params.pattern || !request.params.tab || !request.body || !request.body.nodes || !request.body.nodes.affected_items || !request.body.nodes.name || request.params.tab && !request.params.tab.includes('cluster-')) {
        throw new Error('Missing parameters creating visualizations');
      }

      const type = request.params.tab.split('-')[1];
      const file = _visualizations.ClusterVisualizations[type];
      const nodes = request.body.nodes.affected_items;
      const name = request.body.nodes.name;
      const masterNode = request.body.nodes.master_node;
      const {
        id: patternID,
        title: patternName
      } = request.body.pattern;
      const raw = await this.buildClusterVisualizationsRaw(file, patternID, nodes, name, masterNode, patternName);
      return response.ok({
        body: {
          acknowledge: true,
          raw: raw
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createClusterVis', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4009, 500, response);
    }
  }
  /**
   * This checks if there is sample alerts
   * GET /elastic/samplealerts
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {alerts: [...]} or ErrorResponse
   */


  async haveSampleAlerts(context, request, response) {
    try {
      // Check if wazuh sample alerts index exists
      const results = await Promise.all(Object.keys(_constants.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS).map(category => context.core.opensearch.client.asCurrentUser.indices.exists({
        index: this.buildSampleIndexByCategory(category)
      })));
      return response.ok({
        body: {
          sampleAlertsInstalled: results.some(result => result.body)
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)('Sample Alerts category not valid', 1000, 500, response);
    }
  }
  /**
   * This creates sample alerts in wazuh-sample-alerts
   * GET /elastic/samplealerts/{category}
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {alerts: [...]} or ErrorResponse
   */


  async haveSampleAlertsOfCategory(context, request, response) {
    try {
      const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category); // Check if wazuh sample alerts index exists

      const existsSampleIndex = await context.core.opensearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });
      return response.ok({
        body: {
          index: sampleAlertsIndex,
          exists: existsSampleIndex.body
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:haveSampleAlertsOfCategory', `Error checking if there are sample alerts indices: ${error.message || error}`);
      const [statusCode, errorMessage] = this.getErrorDetails(error);
      return (0, _errorResponse.ErrorResponse)(`Error checking if there are sample alerts indices: ${errorMessage || error}`, 1000, statusCode, response);
    }
  }
  /**
   * This creates sample alerts in wazuh-sample-alerts
   * POST /elastic/samplealerts/{category}
   * {
   *   "manager": {
   *      "name": "manager_name"
   *    },
   *    cluster: {
   *      name: "mycluster",
   *      node: "mynode"
   *    }
   * }
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {index: string, alerts: [...], count: number} or ErrorResponse
   */


  async createSampleAlerts(context, request, response) {
    const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category);

    try {
      // Check if user has administrator role in token
      const token = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

      if (!token) {
        return (0, _errorResponse.ErrorResponse)('No token provided', 401, 401, response);
      }

      ;
      const decodedToken = (0, _jwtDecode.default)(token);

      if (!decodedToken) {
        return (0, _errorResponse.ErrorResponse)('No permissions in token', 401, 401, response);
      }

      ;

      if (!decodedToken.rbac_roles || !decodedToken.rbac_roles.includes(_constants.WAZUH_ROLE_ADMINISTRATOR_ID)) {
        return (0, _errorResponse.ErrorResponse)('No administrator role', 401, 401, response);
      }

      ; // Check the provided token is valid

      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!apiHostID) {
        return (0, _errorResponse.ErrorResponse)('No API id provided', 401, 401, response);
      }

      ;
      const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', `//`, {}, {
        apiHostID
      });

      if (responseTokenIsWorking.status !== 200) {
        return (0, _errorResponse.ErrorResponse)('Token is not valid', 500, 500, response);
      }

      ;
      const bulkPrefix = JSON.stringify({
        index: {
          _index: sampleAlertsIndex
        }
      });
      const alertGenerateParams = request.body && request.body.params || {};

      const sampleAlerts = _constants.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS[request.params.category].map(typeAlert => (0, _generateAlertsScript.generateAlerts)({ ...typeAlert,
        ...alertGenerateParams
      }, request.body.alerts || typeAlert.alerts || _constants.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS)).flat();

      const bulk = sampleAlerts.map(sampleAlert => `${bulkPrefix}\n${JSON.stringify(sampleAlert)}\n`).join(''); // Index alerts
      // Check if wazuh sample alerts index exists

      const existsSampleIndex = await context.core.opensearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });

      if (!existsSampleIndex.body) {
        // Create wazuh sample alerts index
        const configuration = {
          settings: {
            index: {
              number_of_shards: _constants.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS,
              number_of_replicas: _constants.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS
            }
          }
        };
        await context.core.opensearch.client.asCurrentUser.indices.create({
          index: sampleAlertsIndex,
          body: configuration
        });
        (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Created ${sampleAlertsIndex} index`, 'debug');
      }

      await context.core.opensearch.client.asCurrentUser.bulk({
        index: sampleAlertsIndex,
        body: bulk
      });
      (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Added sample alerts to ${sampleAlertsIndex} index`, 'debug');
      return response.ok({
        body: {
          index: sampleAlertsIndex,
          alertCount: sampleAlerts.length
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Error adding sample alerts to ${sampleAlertsIndex} index: ${error.message || error}`);
      const [statusCode, errorMessage] = this.getErrorDetails(error);
      return (0, _errorResponse.ErrorResponse)(errorMessage || error, 1000, statusCode, response);
    }
  }
  /**
   * This deletes sample alerts
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {result: "deleted", index: string} or ErrorResponse
   */


  async deleteSampleAlerts(context, request, response) {
    // Delete Wazuh sample alert index
    const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category);

    try {
      // Check if user has administrator role in token
      const token = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

      if (!token) {
        return (0, _errorResponse.ErrorResponse)('No token provided', 401, 401, response);
      }

      ;
      const decodedToken = (0, _jwtDecode.default)(token);

      if (!decodedToken) {
        return (0, _errorResponse.ErrorResponse)('No permissions in token', 401, 401, response);
      }

      ;

      if (!decodedToken.rbac_roles || !decodedToken.rbac_roles.includes(_constants.WAZUH_ROLE_ADMINISTRATOR_ID)) {
        return (0, _errorResponse.ErrorResponse)('No administrator role', 401, 401, response);
      }

      ; // Check the provided token is valid

      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!apiHostID) {
        return (0, _errorResponse.ErrorResponse)('No API id provided', 401, 401, response);
      }

      ;
      const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', `//`, {}, {
        apiHostID
      });

      if (responseTokenIsWorking.status !== 200) {
        return (0, _errorResponse.ErrorResponse)('Token is not valid', 500, 500, response);
      }

      ; // Check if Wazuh sample alerts index exists

      const existsSampleIndex = await context.core.opensearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });

      if (existsSampleIndex.body) {
        // Delete Wazuh sample alerts index
        await context.core.opensearch.client.asCurrentUser.indices.delete({
          index: sampleAlertsIndex
        });
        (0, _logger.log)('wazuh-elastic:deleteSampleAlerts', `Deleted ${sampleAlertsIndex} index`, 'debug');
        return response.ok({
          body: {
            result: 'deleted',
            index: sampleAlertsIndex
          }
        });
      } else {
        return (0, _errorResponse.ErrorResponse)(`${sampleAlertsIndex} index doesn't exist`, 1000, 500, response);
      }
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:deleteSampleAlerts', `Error deleting sample alerts of ${sampleAlertsIndex} index: ${error.message || error}`);
      const [statusCode, errorMessage] = this.getErrorDetails(error);
      return (0, _errorResponse.ErrorResponse)(errorMessage || error, 1000, statusCode, response);
    }
  }

  async alerts(context, request, response) {
    try {
      const data = await context.core.opensearch.client.asCurrentUser.search(request.body);
      return response.ok({
        body: data.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:alerts', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4010, 500, response);
    }
  } // Check if there are indices for Statistics


  async existStatisticsIndices(context, request, response) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      const statisticsPattern = `${config['cron.prefix'] || 'wazuh'}-${config['cron.statistics.index.name'] || 'statistics'}*`; //TODO: replace by default as constants instead hardcoded ('wazuh' and 'statistics')

      const existIndex = await context.core.opensearch.client.asCurrentUser.indices.exists({
        index: statisticsPattern,
        allow_no_indices: false
      });
      return response.ok({
        body: existIndex.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:existsStatisticsIndices', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 1000, 500, response);
    }
  }

  getErrorDetails(error) {
    var _error$meta;

    const statusCode = (error === null || error === void 0 ? void 0 : (_error$meta = error.meta) === null || _error$meta === void 0 ? void 0 : _error$meta.statusCode) || 500;
    let errorMessage = error.message;

    if (statusCode === 403) {
      var _error$meta2, _error$meta2$body, _error$meta2$body$err;

      errorMessage = (error === null || error === void 0 ? void 0 : (_error$meta2 = error.meta) === null || _error$meta2 === void 0 ? void 0 : (_error$meta2$body = _error$meta2.body) === null || _error$meta2$body === void 0 ? void 0 : (_error$meta2$body$err = _error$meta2$body.error) === null || _error$meta2$body$err === void 0 ? void 0 : _error$meta2$body$err.reason) || 'Permission denied';
    }

    return [statusCode, errorMessage];
  }

}

exports.WazuhElasticCtrl = WazuhElasticCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWVsYXN0aWMudHMiXSwibmFtZXMiOlsiV2F6dWhFbGFzdGljQ3RybCIsImNvbnN0cnVjdG9yIiwid3pTYW1wbGVBbGVydHNJbmRleFByZWZpeCIsImdldFNhbXBsZUFsZXJ0UHJlZml4IiwibWFuYWdlSG9zdHMiLCJNYW5hZ2VIb3N0cyIsImJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5IiwiY2F0ZWdvcnkiLCJjb25maWciLCJnZXRUZW1wbGF0ZSIsImNvbnRleHQiLCJyZXF1ZXN0IiwicmVzcG9uc2UiLCJkYXRhIiwiY29yZSIsIm9wZW5zZWFyY2giLCJjbGllbnQiLCJhc0ludGVybmFsVXNlciIsImNhdCIsInRlbXBsYXRlcyIsImJvZHkiLCJFcnJvciIsImxhc3RDaGFyIiwicGFyYW1zIiwicGF0dGVybiIsImxlbmd0aCIsInRtcGRhdGEiLCJtYXRjaCIsInRtcGFycmF5IiwiaXRlbSIsImluY2x1ZGVzIiwic3Vic3RyIiwic2xpY2UiLCJzdWJJdGVtcyIsInNwbGl0Iiwic3ViaXRlbSIsInB1c2giLCJ0cmltIiwiYXJyYXkiLCJmaWx0ZXIiLCJpc0luY2x1ZGVkIiwiQXJyYXkiLCJpc0FycmF5Iiwib2siLCJzdGF0dXNDb2RlIiwic3RhdHVzIiwiZXJyb3IiLCJtZXNzYWdlIiwiY2hlY2tQYXR0ZXJuIiwic2F2ZWRPYmplY3RzIiwiZmluZCIsInR5cGUiLCJleGlzdHNJbmRleFBhdHRlcm4iLCJzYXZlZF9vYmplY3RzIiwiYXR0cmlidXRlcyIsInRpdGxlIiwiZ2V0RmllbGRUb3AiLCJwYXlsb2FkIiwic2l6ZSIsInF1ZXJ5IiwiYm9vbCIsIm11c3QiLCJtdXN0X25vdCIsInRlcm0iLCJyYW5nZSIsInRpbWVzdGFtcCIsImFnZ3MiLCJ0ZXJtcyIsImZpZWxkIiwib3JkZXIiLCJfY291bnQiLCJ0aW1lR1RFIiwidGltZUxUIiwibW9kZSIsImNsdXN0ZXIiLCJhZ2VudHNMaXN0IiwiYXNDdXJyZW50VXNlciIsInNlYXJjaCIsImluZGV4IiwiaGl0cyIsInRvdGFsIiwidmFsdWUiLCJhZ2dyZWdhdGlvbnMiLCJidWNrZXRzIiwia2V5IiwiZmlsdGVyQWxsb3dlZEluZGV4UGF0dGVybkxpc3QiLCJsaXN0IiwicmVxIiwiZmluYWxMaXN0IiwicmVzdWx0cyIsImZvcmJpZGRlbiIsInZhbGlkYXRlSW5kZXhQYXR0ZXJuIiwiaW5kZXhQYXR0ZXJuTGlzdCIsIm1pbmltdW0iLCJ2YWxpZCIsInBhcnNlZCIsIkpTT04iLCJwYXJzZSIsImZpZWxkcyIsIm5hbWUiLCJpZCIsImdldEN1cnJlbnRQbGF0Zm9ybSIsInBsYXRmb3JtIiwid2F6dWgiLCJzZWN1cml0eSIsImJ1aWxkVmlzdWFsaXphdGlvbnNSYXciLCJhcHBfb2JqZWN0cyIsIm5hbWVzcGFjZSIsIm1vbml0b3JpbmdQYXR0ZXJuIiwidmlzQXJyYXkiLCJhdXhfc291cmNlIiwiYnVsa19jb250ZW50IiwiZWxlbWVudCIsInN0cmluZ2lmeSIsIl9zb3VyY2UiLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiZGVmYXVsdFN0ciIsImlzTW9uaXRvcmluZyIsInJlcGxhY2UiLCJ2aXNTdGF0ZSIsIl90eXBlIiwidmlzdWFsaXphdGlvbiIsIl9pZCIsIl92ZXJzaW9uIiwidmVyc2lvbiIsIlByb21pc2UiLCJyZWplY3QiLCJidWlsZENsdXN0ZXJWaXN1YWxpemF0aW9uc1JhdyIsIm5vZGVzIiwibWFzdGVyX25vZGUiLCJwYXR0ZXJuX25hbWUiLCJub2RlIiwic3Vic3RyaW5nIiwic3RhcnRzV2l0aCIsImV4cHJlc3Npb24iLCJleHByZXNzaW9uUmVnZXgiLCJfdmlzU3RhdGUiLCJ2aXNTdGF0ZUJ5Tm9kZSIsImNyZWF0ZVZpcyIsInRhYiIsInRhYlByZWZpeCIsInRhYlNwbGl0IiwidGFiU3VmaXgiLCJmaWxlIiwiT3ZlcnZpZXdWaXN1YWxpemF0aW9ucyIsIkFnZW50c1Zpc3VhbGl6YXRpb25zIiwibm90Rm91bmQiLCJyYXciLCJhY2tub3dsZWRnZSIsImNyZWF0ZUNsdXN0ZXJWaXMiLCJhZmZlY3RlZF9pdGVtcyIsIkNsdXN0ZXJWaXN1YWxpemF0aW9ucyIsIm1hc3Rlck5vZGUiLCJwYXR0ZXJuSUQiLCJwYXR0ZXJuTmFtZSIsImhhdmVTYW1wbGVBbGVydHMiLCJhbGwiLCJPYmplY3QiLCJrZXlzIiwiV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SSUVTX1RZUEVfQUxFUlRTIiwibWFwIiwiaW5kaWNlcyIsImV4aXN0cyIsInNhbXBsZUFsZXJ0c0luc3RhbGxlZCIsInNvbWUiLCJyZXN1bHQiLCJoYXZlU2FtcGxlQWxlcnRzT2ZDYXRlZ29yeSIsInNhbXBsZUFsZXJ0c0luZGV4IiwiZXhpc3RzU2FtcGxlSW5kZXgiLCJlcnJvck1lc3NhZ2UiLCJnZXRFcnJvckRldGFpbHMiLCJjcmVhdGVTYW1wbGVBbGVydHMiLCJ0b2tlbiIsImhlYWRlcnMiLCJjb29raWUiLCJkZWNvZGVkVG9rZW4iLCJyYmFjX3JvbGVzIiwiV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lEIiwiYXBpSG9zdElEIiwicmVzcG9uc2VUb2tlbklzV29ya2luZyIsImFwaSIsImJ1bGtQcmVmaXgiLCJfaW5kZXgiLCJhbGVydEdlbmVyYXRlUGFyYW1zIiwic2FtcGxlQWxlcnRzIiwidHlwZUFsZXJ0IiwiYWxlcnRzIiwiV0FaVUhfU0FNUExFX0FMRVJUU19ERUZBVUxUX05VTUJFUl9BTEVSVFMiLCJmbGF0IiwiYnVsayIsInNhbXBsZUFsZXJ0Iiwiam9pbiIsImNvbmZpZ3VyYXRpb24iLCJzZXR0aW5ncyIsIm51bWJlcl9vZl9zaGFyZHMiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1NIQVJEUyIsIm51bWJlcl9vZl9yZXBsaWNhcyIsIldBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfUkVQTElDQVMiLCJjcmVhdGUiLCJhbGVydENvdW50IiwiZGVsZXRlU2FtcGxlQWxlcnRzIiwiZGVsZXRlIiwiZXhpc3RTdGF0aXN0aWNzSW5kaWNlcyIsInN0YXRpc3RpY3NQYXR0ZXJuIiwiZXhpc3RJbmRleCIs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LENBQXFEQyxNQUFyRCxDQUE0RDtBQUNuRnJGLFFBQUFBLEtBQUssRUFBRThILGlCQUQ0RTtBQUVuRkUsUUFBQUEsZ0JBQWdCLEVBQUU7QUFGaUUsT0FBNUQsQ0FBekI7QUFJQSxhQUFPbE0sUUFBUSxDQUFDK0IsRUFBVCxDQUFZO0FBQ2pCdkIsUUFBQUEsSUFBSSxFQUFFeUwsVUFBVSxDQUFDekw7QUFEQSxPQUFaLENBQVA7QUFHRCxLQVZELENBVUUsT0FBTzBCLEtBQVAsRUFBYztBQUNkLHVCQUFJLHVDQUFKLEVBQTZDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQTlEO0FBQ0EsYUFBTyxrQ0FBY0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUEvQixFQUFzQyxJQUF0QyxFQUE0QyxHQUE1QyxFQUFpRGxDLFFBQWpELENBQVA7QUFDRDtBQUNGOztBQUVEK0osRUFBQUEsZUFBZSxDQUFDN0gsS0FBRCxFQUFPO0FBQUE7O0FBQ3BCLFVBQU1GLFVBQVUsR0FBRyxDQUFBRSxLQUFLLFNBQUwsSUFBQUEsS0FBSyxXQUFMLDJCQUFBQSxLQUFLLENBQUVpSyxJQUFQLDREQUFhbkssVUFBYixLQUEyQixHQUE5QztBQUNBLFFBQUk4SCxZQUFZLEdBQUc1SCxLQUFLLENBQUNDLE9BQXpCOztBQUVBLFFBQUdILFVBQVUsS0FBSyxHQUFsQixFQUFzQjtBQUFBOztBQUNwQjhILE1BQUFBLFlBQVksR0FBRyxDQUFBNUgsS0FBSyxTQUFMLElBQUFBLEtBQUssV0FBTCw0QkFBQUEsS0FBSyxDQUFFaUssSUFBUCxtRkFBYTNMLElBQWIsaUdBQW1CMEIsS0FBbkIsZ0ZBQTBCa0ssTUFBMUIsS0FBb0MsbUJBQW5EO0FBQ0Q7O0FBRUQsV0FBTyxDQUFDcEssVUFBRCxFQUFhOEgsWUFBYixDQUFQO0FBQ0Q7O0FBL3pCMkIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gQ2xhc3MgZm9yIFdhenVoLUVsYXN0aWMgZnVuY3Rpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHsgRXJyb3JSZXNwb25zZSB9IGZyb20gJy4uL2xpYi9lcnJvci1yZXNwb25zZSc7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuLi9saWIvbG9nZ2VyJztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHtcbiAgQWdlbnRzVmlzdWFsaXphdGlvbnMsXG4gIE92ZXJ2aWV3VmlzdWFsaXphdGlvbnMsXG4gIENsdXN0ZXJWaXN1YWxpemF0aW9uc1xufSBmcm9tICcuLi9pbnRlZ3JhdGlvbi1maWxlcy92aXN1YWxpemF0aW9ucyc7XG5cbmltcG9ydCB7IGdlbmVyYXRlQWxlcnRzIH0gZnJvbSAnLi4vbGliL2dlbmVyYXRlLWFsZXJ0cy9nZW5lcmF0ZS1hbGVydHMtc2NyaXB0JztcbmltcG9ydCB7IFdBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9JRCwgV0FaVUhfU0FNUExFX0FMRVJUU19JTkRFWF9TSEFSRFMsIFdBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfUkVQTElDQVMgfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJztcbmltcG9ydCBqd3REZWNvZGUgZnJvbSAnand0LWRlY29kZSc7XG5pbXBvcnQgeyBNYW5hZ2VIb3N0cyB9IGZyb20gJy4uL2xpYi9tYW5hZ2UtaG9zdHMnO1xuaW1wb3J0IHsgT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5LCBTYXZlZE9iamVjdCwgU2F2ZWRPYmplY3RzRmluZFJlc3BvbnNlIH0gZnJvbSAnc3JjL2NvcmUvc2VydmVyJztcbmltcG9ydCB7IGdldENvb2tpZVZhbHVlQnlOYW1lIH0gZnJvbSAnLi4vbGliL2Nvb2tpZSc7XG5pbXBvcnQgeyBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JJRVNfVFlQRV9BTEVSVFMsIFdBWlVIX1NBTVBMRV9BTEVSVFNfREVGQVVMVF9OVU1CRVJfQUxFUlRTIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IGdldFNldHRpbmdEZWZhdWx0VmFsdWUgfSBmcm9tICcuLi8uLi9jb21tb24vc2VydmljZXMvc2V0dGluZ3MnO1xuXG5leHBvcnQgY2xhc3MgV2F6dWhFbGFzdGljQ3RybCB7XG4gIHd6U2FtcGxlQWxlcnRzSW5kZXhQcmVmaXg6IHN0cmluZ1xuICBtYW5hZ2VIb3N0czogTWFuYWdlSG9zdHNcbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy53elNhbXBsZUFsZXJ0c0luZGV4UHJlZml4ID0gdGhpcy5nZXRTYW1wbGVBbGVydFByZWZpeCgpO1xuICAgIHRoaXMubWFuYWdlSG9zdHMgPSBuZXcgTWFuYWdlSG9zdHMoKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHJldHVybnMgdGhlIGluZGV4IGFjY29yZGluZyB0aGUgY2F0ZWdvcnlcbiAgICogQHBhcmFtIHtzdHJpbmd9IGNhdGVnb3J5XG4gICAqL1xuICBidWlsZFNhbXBsZUluZGV4QnlDYXRlZ29yeShjYXRlZ29yeTogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy53elNhbXBsZUFsZXJ0c0luZGV4UHJlZml4fXNhbXBsZS0ke2NhdGVnb3J5fWA7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyByZXR1cm5zIHRoZSBkZWZpbmVkIGNvbmZpZyBmb3Igc2FtcGxlIGFsZXJ0cyBwcmVmaXggb3IgdGhlIGRlZmF1bHQgdmFsdWUuXG4gICAqL1xuICBnZXRTYW1wbGVBbGVydFByZWZpeCgpOiBzdHJpbmcge1xuICAgIGNvbnN0IGNvbmZpZyA9IGdldENvbmZpZ3VyYXRpb24oKTtcbiAgICByZXR1cm4gY29uZmlnWydhbGVydHMuc2FtcGxlLnByZWZpeCddIHx8IGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ2FsZXJ0cy5zYW1wbGUucHJlZml4Jyk7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyByZXRyaWV2ZXMgYSB0ZW1wbGF0ZSBmcm9tIEVsYXN0aWNzZWFyY2hcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IHRlbXBsYXRlIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGdldFRlbXBsYXRlKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0PHsgcGF0dGVybjogc3RyaW5nIH0+LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5jYXQudGVtcGxhdGVzKCk7XG5cbiAgICAgIGNvbnN0IHRlbXBsYXRlcyA9IGRhdGEuYm9keTtcbiAgICAgIGlmICghdGVtcGxhdGVzIHx8IHR5cGVvZiB0ZW1wbGF0ZXMgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnQW4gdW5rbm93biBlcnJvciBvY2N1cnJlZCB3aGVuIGZldGNoaW5nIHRlbXBsYXRlcyBmcm9tIEVsYXN0aWNzZWFjaCdcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgbGFzdENoYXIgPSByZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuW3JlcXVlc3QucGFyYW1zLnBhdHRlcm4ubGVuZ3RoIC0gMV07XG5cbiAgICAgIC8vIFNwbGl0IGludG8gc2VwYXJhdGUgcGF0dGVybnNcbiAgICAgIGNvbnN0IHRtcGRhdGEgPSB0ZW1wbGF0ZXMubWF0Y2goL1xcWy4qXFxdL2cpO1xuICAgICAgY29uc3QgdG1wYXJyYXkgPSBbXTtcbiAgICAgIGZvciAobGV0IGl0ZW0gb2YgdG1wZGF0YSkge1xuICAgICAgICAvLyBBIHRlbXBsYXRlIG1pZ2h0IHVzZSBtb3JlIHRoYW4gb25lIHBhdHRlcm5cbiAgICAgICAgaWYgKGl0ZW0uaW5jbHVkZXMoJywnKSkge1xuICAgICAgICAgIGl0ZW0gPSBpdGVtLnN1YnN0cigxKS5zbGljZSgwLCAtMSk7XG4gICAgICAgICAgY29uc3Qgc3ViSXRlbXMgPSBpdGVtLnNwbGl0KCcsJyk7XG4gICAgICAgICAgZm9yIChjb25zdCBzdWJpdGVtIG9mIHN1Ykl0ZW1zKSB7XG4gICAgICAgICAgICB0bXBhcnJheS5wdXNoKGBbJHtzdWJpdGVtLnRyaW0oKX1dYCk7XG4gICAgICAgICAgfVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRtcGFycmF5LnB1c2goaXRlbSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy8gRW5zdXJlIHdlIGFyZSBoYW5kbGluZyBqdXN0IHBhdHRlcm5zXG4gICAgICBjb25zdCBhcnJheSA9IHRtcGFycmF5LmZpbHRlcihcbiAgICAgICAgaXRlbSA9PiBpdGVtLmluY2x1ZGVzKCdbJykgJiYgaXRlbS5pbmNsdWRlcygnXScpXG4gICAgICApO1xuXG4gICAgICBjb25zdCBwYXR0ZXJuID1cbiAgICAgICAgbGFzdENoYXIgPT09ICcqJyA/IHJlcXVlc3QucGFyYW1zLnBhdHRlcm4uc2xpY2UoMCwgLTEpIDogcmVxdWVzdC5wYXJhbXMucGF0dGVybjtcbiAgICAgIGNvbnN0IGlzSW5jbHVkZWQgPSBhcnJheS5maWx0ZXIoaXRlbSA9PiB7XG4gICAgICAgIGl0ZW0gPSBpdGVtLnNsaWNlKDEsIC0xKTtcbiAgICAgICAgY29uc3QgbGFzdENoYXIgPSBpdGVtW2l0ZW0ubGVuZ3RoIC0gMV07XG4gICAgICAgIGl0ZW0gPSBsYXN0Q2hhciA9PT0gJyonID8gaXRlbS5zbGljZSgwLCAtMSkgOiBpdGVtO1xuICAgICAgICByZXR1cm4gaXRlbS5pbmNsdWRlcyhwYXR0ZXJuKSB8fCBwYXR0ZXJuLmluY2x1ZGVzKGl0ZW0pO1xuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmdldFRlbXBsYXRlJyxcbiAgICAgICAgYFRlbXBsYXRlIGlzIHZhbGlkOiAke2lzSW5jbHVkZWQgJiYgQXJyYXkuaXNBcnJheShpc0luY2x1ZGVkKSAmJiBpc0luY2x1ZGVkLmxlbmd0aFxuICAgICAgICAgID8gJ3llcydcbiAgICAgICAgICA6ICdubydcbiAgICAgICAgfWAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gaXNJbmNsdWRlZCAmJiBBcnJheS5pc0FycmF5KGlzSW5jbHVkZWQpICYmIGlzSW5jbHVkZWQubGVuZ3RoXG4gICAgICAgID8gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICAgIHN0YXR1czogdHJ1ZSxcbiAgICAgICAgICAgIGRhdGE6IGBUZW1wbGF0ZSBmb3VuZCBmb3IgJHtyZXF1ZXN0LnBhcmFtcy5wYXR0ZXJufWBcbiAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgICAgIDogcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICAgIHN0YXR1czogZmFsc2UsXG4gICAgICAgICAgICBkYXRhOiBgTm8gdGVtcGxhdGUgZm91bmQgZm9yICR7cmVxdWVzdC5wYXJhbXMucGF0dGVybn1gXG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmdldFRlbXBsYXRlJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShcbiAgICAgICAgYENvdWxkIG5vdCByZXRyaWV2ZSB0ZW1wbGF0ZXMgZnJvbSBFbGFzdGljc2VhcmNoIGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHxcbiAgICAgICAgZXJyb3J9YCxcbiAgICAgICAgNDAwMixcbiAgICAgICAgNTAwLFxuICAgICAgICByZXNwb25zZVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBjaGVjayBpbmRleC1wYXR0ZXJuXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBzdGF0dXMgb2JqIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNoZWNrUGF0dGVybihjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdDx7IHBhdHRlcm46IHN0cmluZyB9PiwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBjb250ZXh0LmNvcmUuc2F2ZWRPYmplY3RzLmNsaWVudC5maW5kPFNhdmVkT2JqZWN0c0ZpbmRSZXNwb25zZTxTYXZlZE9iamVjdD4+KHsgdHlwZTogJ2luZGV4LXBhdHRlcm4nIH0pO1xuXG4gICAgICBjb25zdCBleGlzdHNJbmRleFBhdHRlcm4gPSBkYXRhLnNhdmVkX29iamVjdHMuZmluZChcbiAgICAgICAgaXRlbSA9PiBpdGVtLmF0dHJpYnV0ZXMudGl0bGUgPT09IHJlcXVlc3QucGFyYW1zLnBhdHRlcm5cbiAgICAgICk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmNoZWNrUGF0dGVybicsXG4gICAgICAgIGBJbmRleCBwYXR0ZXJuIGZvdW5kOiAke2V4aXN0c0luZGV4UGF0dGVybiA/IGV4aXN0c0luZGV4UGF0dGVybi5hdHRyaWJ1dGVzLnRpdGxlIDogJ25vJ31gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgcmV0dXJuIGV4aXN0c0luZGV4UGF0dGVyblxuICAgICAgICA/IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7IHN0YXR1c0NvZGU6IDIwMCwgc3RhdHVzOiB0cnVlLCBkYXRhOiAnSW5kZXggcGF0dGVybiBmb3VuZCcgfVxuICAgICAgICB9KVxuICAgICAgICA6IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiA1MDAsXG4gICAgICAgICAgICBzdGF0dXM6IGZhbHNlLFxuICAgICAgICAgICAgZXJyb3I6IDEwMDIwLFxuICAgICAgICAgICAgbWVzc2FnZTogJ0luZGV4IHBhdHRlcm4gbm90IGZvdW5kJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpjaGVja1BhdHRlcm4nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICBgU29tZXRoaW5nIHdlbnQgd3JvbmcgcmV0cmlldmluZyBpbmRleC1wYXR0ZXJucyBmcm9tIEVsYXN0aWNzZWFyY2ggZHVlIHRvICR7ZXJyb3IubWVzc2FnZSB8fFxuICAgICAgICBlcnJvcn1gLFxuICAgICAgICA0MDAzLFxuICAgICAgICA1MDAsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGdldCB0aGUgZmllbGRzIGtleXNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtBcnJheTxPYmplY3Q+fSBmaWVsZHMgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0RmllbGRUb3AoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3Q8eyBtb2RlOiBzdHJpbmcsIGNsdXN0ZXI6IHN0cmluZywgZmllbGQ6IHN0cmluZywgcGF0dGVybjogc3RyaW5nIH0sIHsgYWdlbnRzTGlzdDogc3RyaW5nIH0+LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgLy8gVG9wIGZpZWxkIHBheWxvYWRcbiAgICAgIGxldCBwYXlsb2FkID0ge1xuICAgICAgICBzaXplOiAxLFxuICAgICAgICBxdWVyeToge1xuICAgICAgICAgIGJvb2w6IHtcbiAgICAgICAgICAgIG11c3Q6IFtdLFxuICAgICAgICAgICAgbXVzdF9ub3Q6IHtcbiAgICAgICAgICAgICAgdGVybToge1xuICAgICAgICAgICAgICAgICdhZ2VudC5pZCc6ICcwMDAnXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJhbmdlOiB7IHRpbWVzdGFtcDoge30gfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICBdXG4gICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiB7XG4gICAgICAgICAgJzInOiB7XG4gICAgICAgICAgICB0ZXJtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJycsXG4gICAgICAgICAgICAgIHNpemU6IDEsXG4gICAgICAgICAgICAgIG9yZGVyOiB7IF9jb3VudDogJ2Rlc2MnIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIC8vIFNldCB1cCB0aW1lIGludGVydmFsLCBkZWZhdWx0IHRvIExhc3QgMjRoXG4gICAgICBjb25zdCB0aW1lR1RFID0gJ25vdy0xZCc7XG4gICAgICBjb25zdCB0aW1lTFQgPSAnbm93JztcbiAgICAgIHBheWxvYWQucXVlcnkuYm9vbC5maWx0ZXJbMF0ucmFuZ2VbJ3RpbWVzdGFtcCddWydndGUnXSA9IHRpbWVHVEU7XG4gICAgICBwYXlsb2FkLnF1ZXJ5LmJvb2wuZmlsdGVyWzBdLnJhbmdlWyd0aW1lc3RhbXAnXVsnbHQnXSA9IHRpbWVMVDtcblxuICAgICAgLy8gU2V0IHVwIG1hdGNoIGZvciBkZWZhdWx0IGNsdXN0ZXIgbmFtZVxuICAgICAgcGF5bG9hZC5xdWVyeS5ib29sLm11c3QucHVzaChcbiAgICAgICAgcmVxdWVzdC5wYXJhbXMubW9kZSA9PT0gJ2NsdXN0ZXInXG4gICAgICAgICAgPyB7IG1hdGNoOiB7ICdjbHVzdGVyLm5hbWUnOiByZXF1ZXN0LnBhcmFtcy5jbHVzdGVyIH0gfVxuICAgICAgICAgIDogeyBtYXRjaDogeyAnbWFuYWdlci5uYW1lJzogcmVxdWVzdC5wYXJhbXMuY2x1c3RlciB9IH1cbiAgICAgICk7XG5cbiAgICAgIGlmKHJlcXVlc3QucXVlcnkuYWdlbnRzTGlzdClcbiAgICAgICAgcGF5bG9hZC5xdWVyeS5ib29sLmZpbHRlci5wdXNoKFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIHRlcm1zOiB7XG4gICAgICAgICAgICAgICdhZ2VudC5pZCc6IHJlcXVlc3QucXVlcnkuYWdlbnRzTGlzdC5zcGxpdCgnLCcpXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICApO1xuICAgICAgcGF5bG9hZC5hZ2dzWycyJ10udGVybXMuZmllbGQgPSByZXF1ZXN0LnBhcmFtcy5maWVsZDtcblxuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaCh7XG4gICAgICAgIHNpemU6IDEsXG4gICAgICAgIGluZGV4OiByZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuLFxuICAgICAgICBib2R5OiBwYXlsb2FkXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGRhdGEuYm9keS5oaXRzLnRvdGFsLnZhbHVlID09PSAwIHx8XG4gICAgICAgIHR5cGVvZiBkYXRhLmJvZHkuYWdncmVnYXRpb25zWycyJ10uYnVja2V0c1swXSA9PT0gJ3VuZGVmaW5lZCdcbiAgICAgICAgPyByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keTogeyBzdGF0dXNDb2RlOiAyMDAsIGRhdGE6ICcnIH1cbiAgICAgICAgfSlcbiAgICAgICAgOiByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgc3RhdHVzQ29kZTogMjAwLFxuICAgICAgICAgICAgZGF0YTogZGF0YS5ib2R5LmFnZ3JlZ2F0aW9uc1snMiddLmJ1Y2tldHNbMF0ua2V5XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmdldEZpZWxkVG9wJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA0MDA0LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tzIG9uZSBieSBvbmUgaWYgdGhlIHJlcXVlc3RpbmcgdXNlciBoYXMgZW5vdWdoIHByaXZpbGVnZXMgdG8gdXNlXG4gICAqIGFuIGluZGV4IHBhdHRlcm4gZnJvbSB0aGUgbGlzdC5cbiAgICogQHBhcmFtIHtBcnJheTxPYmplY3Q+fSBsaXN0IExpc3Qgb2YgaW5kZXggcGF0dGVybnNcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcVxuICAgKiBAcmV0dXJucyB7QXJyYXk8T2JqZWN0Pn0gTGlzdCBvZiBhbGxvd2VkIGluZGV4XG4gICAqL1xuICBhc3luYyBmaWx0ZXJBbGxvd2VkSW5kZXhQYXR0ZXJuTGlzdChjb250ZXh0LCBsaXN0LCByZXEpIHtcbiAgICAvL1RPRE86IHJldmlldyBpZiBuZWNlc2FyeSB0byBkZWxldGVcbiAgICBsZXQgZmluYWxMaXN0ID0gW107XG4gICAgZm9yIChsZXQgaXRlbSBvZiBsaXN0KSB7XG4gICAgICBsZXQgcmVzdWx0cyA9IGZhbHNlLFxuICAgICAgICBmb3JiaWRkZW4gPSBmYWxzZTtcbiAgICAgIHRyeSB7XG4gICAgICAgIHJlc3VsdHMgPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5zZWFyY2goe1xuICAgICAgICAgIGluZGV4OiBpdGVtLnRpdGxlXG4gICAgICAgIH0pO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgZm9yYmlkZGVuID0gdHJ1ZTtcbiAgICAgIH1cbiAgICAgIGlmIChcbiAgICAgICAgKCgocmVzdWx0cyB8fCB7fSkuYm9keSB8fCB7fSkuaGl0cyB8fCB7fSkudG90YWwudmFsdWUgPj0gMSB8fFxuICAgICAgICAoIWZvcmJpZGRlbiAmJiAoKChyZXN1bHRzIHx8IHt9KS5ib2R5IHx8IHt9KS5oaXRzIHx8IHt9KS50b3RhbCA9PT0gMClcbiAgICAgICkge1xuICAgICAgICBmaW5hbExpc3QucHVzaChpdGVtKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGZpbmFsTGlzdDtcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGVja3MgZm9yIG1pbmltdW0gaW5kZXggcGF0dGVybiBmaWVsZHMgaW4gYSBsaXN0IG9mIGluZGV4IHBhdHRlcm5zLlxuICAgKiBAcGFyYW0ge0FycmF5PE9iamVjdD59IGluZGV4UGF0dGVybkxpc3QgTGlzdCBvZiBpbmRleCBwYXR0ZXJuc1xuICAgKi9cbiAgdmFsaWRhdGVJbmRleFBhdHRlcm4oaW5kZXhQYXR0ZXJuTGlzdCkge1xuICAgIGNvbnN0IG1pbmltdW0gPSBbJ3RpbWVzdGFtcCcsICdydWxlLmdyb3VwcycsICdtYW5hZ2VyLm5hbWUnLCAnYWdlbnQuaWQnXTtcbiAgICBsZXQgbGlzdCA9IFtdO1xuICAgIGZvciAoY29uc3QgaW5kZXggb2YgaW5kZXhQYXR0ZXJuTGlzdCkge1xuICAgICAgbGV0IHZhbGlkLCBwYXJzZWQ7XG4gICAgICB0cnkge1xuICAgICAgICBwYXJzZWQgPSBKU09OLnBhcnNlKGluZGV4LmF0dHJpYnV0ZXMuZmllbGRzKTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICB2YWxpZCA9IHBhcnNlZC5maWx0ZXIoaXRlbSA9PiBtaW5pbXVtLmluY2x1ZGVzKGl0ZW0ubmFtZSkpO1xuICAgICAgaWYgKHZhbGlkLmxlbmd0aCA9PT0gNCkge1xuICAgICAgICBsaXN0LnB1c2goe1xuICAgICAgICAgIGlkOiBpbmRleC5pZCxcbiAgICAgICAgICB0aXRsZTogaW5kZXguYXR0cmlidXRlcy50aXRsZVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGxpc3Q7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyBjdXJyZW50IHNlY3VyaXR5IHBsYXRmb3JtXG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXFcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcGx5XG4gICAqIEByZXR1cm5zIHtTdHJpbmd9XG4gICAqL1xuICBhc3luYyBnZXRDdXJyZW50UGxhdGZvcm0oY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3Q8eyB1c2VyOiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7XG4gICAgICAgICAgcGxhdGZvcm06IGNvbnRleHQud2F6dWguc2VjdXJpdHkucGxhdGZvcm1cbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpnZXRDdXJyZW50UGxhdGZvcm0nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDQwMTEsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXBsYWNlcyB2aXN1YWxpemF0aW9ucyBtYWluIGZpZWxkcyB0byBmaXQgYSBjZXJ0YWluIHBhdHRlcm4uXG4gICAqIEBwYXJhbSB7QXJyYXk8T2JqZWN0Pn0gYXBwX29iamVjdHMgT2JqZWN0IGNvbnRhaW5pbmcgcmF3IHZpc3VhbGl6YXRpb25zLlxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWQgSW5kZXgtcGF0dGVybiBpZCB0byB1c2UgaW4gdGhlIHZpc3VhbGl6YXRpb25zLiBFZzogJ3dhenVoLWFsZXJ0cydcbiAgICovXG4gIGFzeW5jIGJ1aWxkVmlzdWFsaXphdGlvbnNSYXcoYXBwX29iamVjdHMsIGlkLCBuYW1lc3BhY2UgPSBmYWxzZSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgICBsZXQgbW9uaXRvcmluZ1BhdHRlcm4gPVxuICAgICAgICAoY29uZmlnIHx8IHt9KVsnd2F6dWgubW9uaXRvcmluZy5wYXR0ZXJuJ10gfHwgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgnd2F6dWgubW9uaXRvcmluZy5wYXR0ZXJuJyk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmJ1aWxkVmlzdWFsaXphdGlvbnNSYXcnLFxuICAgICAgICBgQnVpbGRpbmcgJHthcHBfb2JqZWN0cy5sZW5ndGh9IHZpc3VhbGl6YXRpb25zYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3dhenVoLWVsYXN0aWM6YnVpbGRWaXN1YWxpemF0aW9uc1JhdycsXG4gICAgICAgIGBJbmRleCBwYXR0ZXJuIElEOiAke2lkfWAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBjb25zdCB2aXNBcnJheSA9IFtdO1xuICAgICAgbGV0IGF1eF9zb3VyY2UsIGJ1bGtfY29udGVudDtcbiAgICAgIGZvciAobGV0IGVsZW1lbnQgb2YgYXBwX29iamVjdHMpIHtcbiAgICAgICAgYXV4X3NvdXJjZSA9IEpTT04ucGFyc2UoSlNPTi5zdHJpbmdpZnkoZWxlbWVudC5fc291cmNlKSk7XG5cbiAgICAgICAgLy8gUmVwbGFjZSBpbmRleC1wYXR0ZXJuIGZvciB2aXN1YWxpemF0aW9uc1xuICAgICAgICBpZiAoXG4gICAgICAgICAgYXV4X3NvdXJjZSAmJlxuICAgICAgICAgIGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhICYmXG4gICAgICAgICAgYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiAmJlxuICAgICAgICAgIHR5cGVvZiBhdXhfc291cmNlLmtpYmFuYVNhdmVkT2JqZWN0TWV0YS5zZWFyY2hTb3VyY2VKU09OID09PSAnc3RyaW5nJ1xuICAgICAgICApIHtcbiAgICAgICAgICBjb25zdCBkZWZhdWx0U3RyID0gYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTjtcblxuICAgICAgICAgIGNvbnN0IGlzTW9uaXRvcmluZyA9IGRlZmF1bHRTdHIuaW5jbHVkZXMoJ3dhenVoLW1vbml0b3JpbmcnKTtcbiAgICAgICAgICBpZiAoaXNNb25pdG9yaW5nKSB7XG4gICAgICAgICAgICBpZiAobmFtZXNwYWNlICYmIG5hbWVzcGFjZSAhPT0gJ2RlZmF1bHQnKSB7XG4gICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICBtb25pdG9yaW5nUGF0dGVybi5pbmNsdWRlcyhuYW1lc3BhY2UpICYmXG4gICAgICAgICAgICAgICAgbW9uaXRvcmluZ1BhdHRlcm4uaW5jbHVkZXMoJ2luZGV4LXBhdHRlcm46JylcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgbW9uaXRvcmluZ1BhdHRlcm4gPSBtb25pdG9yaW5nUGF0dGVybi5zcGxpdChcbiAgICAgICAgICAgICAgICAgICdpbmRleC1wYXR0ZXJuOidcbiAgICAgICAgICAgICAgICApWzFdO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBhdXhfc291cmNlLmtpYmFuYVNhdmVkT2JqZWN0TWV0YS5zZWFyY2hTb3VyY2VKU09OID0gZGVmYXVsdFN0ci5yZXBsYWNlKFxuICAgICAgICAgICAgICAvd2F6dWgtbW9uaXRvcmluZy9nLFxuICAgICAgICAgICAgICBtb25pdG9yaW5nUGF0dGVyblttb25pdG9yaW5nUGF0dGVybi5sZW5ndGggLSAxXSA9PT0gJyonIHx8XG4gICAgICAgICAgICAgICAgKG5hbWVzcGFjZSAmJiBuYW1lc3BhY2UgIT09ICdkZWZhdWx0JylcbiAgICAgICAgICAgICAgICA/IG1vbml0b3JpbmdQYXR0ZXJuXG4gICAgICAgICAgICAgICAgOiBtb25pdG9yaW5nUGF0dGVybiArICcqJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiA9IGRlZmF1bHRTdHIucmVwbGFjZShcbiAgICAgICAgICAgICAgL3dhenVoLWFsZXJ0cy9nLFxuICAgICAgICAgICAgICBpZFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXBsYWNlIGluZGV4LXBhdHRlcm4gZm9yIHNlbGVjdG9yIHZpc3VhbGl6YXRpb25zXG4gICAgICAgIGlmICh0eXBlb2YgKGF1eF9zb3VyY2UgfHwge30pLnZpc1N0YXRlID09PSAnc3RyaW5nJykge1xuICAgICAgICAgIGF1eF9zb3VyY2UudmlzU3RhdGUgPSBhdXhfc291cmNlLnZpc1N0YXRlLnJlcGxhY2UoXG4gICAgICAgICAgICAvd2F6dWgtYWxlcnRzL2csXG4gICAgICAgICAgICBpZFxuICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBCdWxrIHNvdXJjZVxuICAgICAgICBidWxrX2NvbnRlbnQgPSB7fTtcbiAgICAgICAgYnVsa19jb250ZW50W2VsZW1lbnQuX3R5cGVdID0gYXV4X3NvdXJjZTtcblxuICAgICAgICB2aXNBcnJheS5wdXNoKHtcbiAgICAgICAgICBhdHRyaWJ1dGVzOiBidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbixcbiAgICAgICAgICB0eXBlOiBlbGVtZW50Ll90eXBlLFxuICAgICAgICAgIGlkOiBlbGVtZW50Ll9pZCxcbiAgICAgICAgICBfdmVyc2lvbjogYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmVyc2lvblxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB2aXNBcnJheTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmJ1aWxkVmlzdWFsaXphdGlvbnNSYXcnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlcGxhY2VzIGNsdXN0ZXIgdmlzdWFsaXphdGlvbnMgbWFpbiBmaWVsZHMuXG4gICAqIEBwYXJhbSB7QXJyYXk8T2JqZWN0Pn0gYXBwX29iamVjdHMgT2JqZWN0IGNvbnRhaW5pbmcgcmF3IHZpc3VhbGl6YXRpb25zLlxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWQgSW5kZXgtcGF0dGVybiBpZCB0byB1c2UgaW4gdGhlIHZpc3VhbGl6YXRpb25zLiBFZzogJ3dhenVoLWFsZXJ0cydcbiAgICogQHBhcmFtIHtBcnJheTxTdHJpbmc+fSBub2RlcyBBcnJheSBvZiBub2RlIG5hbWVzLiBFZzogWydub2RlMDEnLCAnbm9kZTAyJ11cbiAgICogQHBhcmFtIHtTdHJpbmd9IG5hbWUgQ2x1c3RlciBuYW1lLiBFZzogJ3dhenVoJ1xuICAgKiBAcGFyYW0ge1N0cmluZ30gbWFzdGVyX25vZGUgTWFzdGVyIG5vZGUgbmFtZS4gRWc6ICdub2RlMDEnXG4gICAqL1xuICBidWlsZENsdXN0ZXJWaXN1YWxpemF0aW9uc1JhdyhcbiAgICBhcHBfb2JqZWN0cyxcbiAgICBpZCxcbiAgICBub2RlcyA9IFtdLFxuICAgIG5hbWUsXG4gICAgbWFzdGVyX25vZGUsXG4gICAgcGF0dGVybl9uYW1lID0gJyonXG4gICkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB2aXNBcnJheSA9IFtdO1xuICAgICAgbGV0IGF1eF9zb3VyY2UsIGJ1bGtfY29udGVudDtcblxuICAgICAgZm9yIChjb25zdCBlbGVtZW50IG9mIGFwcF9vYmplY3RzKSB7XG4gICAgICAgIC8vIFN0cmluZ2lmeSBhbmQgcmVwbGFjZSBpbmRleC1wYXR0ZXJuIGZvciB2aXN1YWxpemF0aW9uc1xuICAgICAgICBhdXhfc291cmNlID0gSlNPTi5zdHJpbmdpZnkoZWxlbWVudC5fc291cmNlKTtcbiAgICAgICAgYXV4X3NvdXJjZSA9IGF1eF9zb3VyY2UucmVwbGFjZSgvd2F6dWgtYWxlcnRzL2csIGlkKTtcbiAgICAgICAgYXV4X3NvdXJjZSA9IEpTT04ucGFyc2UoYXV4X3NvdXJjZSk7XG5cbiAgICAgICAgLy8gQnVsayBzb3VyY2VcbiAgICAgICAgYnVsa19jb250ZW50ID0ge307XG4gICAgICAgIGJ1bGtfY29udGVudFtlbGVtZW50Ll90eXBlXSA9IGF1eF9zb3VyY2U7XG5cbiAgICAgICAgY29uc3QgdmlzU3RhdGUgPSBKU09OLnBhcnNlKGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZpc1N0YXRlKTtcbiAgICAgICAgY29uc3QgdGl0bGUgPSB2aXNTdGF0ZS50aXRsZTtcblxuICAgICAgICBpZiAodmlzU3RhdGUudHlwZSAmJiB2aXNTdGF0ZS50eXBlID09PSAndGltZWxpb24nKSB7XG4gICAgICAgICAgbGV0IHF1ZXJ5ID0gJyc7XG4gICAgICAgICAgaWYgKHRpdGxlID09PSAnV2F6dWggQXBwIENsdXN0ZXIgT3ZlcnZpZXcnKSB7XG4gICAgICAgICAgICBmb3IgKGNvbnN0IG5vZGUgb2Ygbm9kZXMpIHtcbiAgICAgICAgICAgICAgcXVlcnkgKz0gYC5lcyhpbmRleD0ke3BhdHRlcm5fbmFtZX0scT1cImNsdXN0ZXIubmFtZTogJHtuYW1lfSBBTkQgY2x1c3Rlci5ub2RlOiAke25vZGUubmFtZX1cIikubGFiZWwoXCIke25vZGUubmFtZX1cIiksYDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHF1ZXJ5ID0gcXVlcnkuc3Vic3RyaW5nKDAsIHF1ZXJ5Lmxlbmd0aCAtIDEpO1xuICAgICAgICAgIH0gZWxzZSBpZiAodGl0bGUgPT09ICdXYXp1aCBBcHAgQ2x1c3RlciBPdmVydmlldyBNYW5hZ2VyJykge1xuICAgICAgICAgICAgcXVlcnkgKz0gYC5lcyhpbmRleD0ke3BhdHRlcm5fbmFtZX0scT1cImNsdXN0ZXIubmFtZTogJHtuYW1lfVwiKS5sYWJlbChcIiR7bmFtZX0gY2x1c3RlclwiKWA7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmICh0aXRsZS5zdGFydHNXaXRoKCdXYXp1aCBBcHAgU3RhdGlzdGljcycpKSB7XG4gICAgICAgICAgICAgIGNvbnN0IHsgc2VhcmNoU291cmNlSlNPTiB9ID0gYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24ua2liYW5hU2F2ZWRPYmplY3RNZXRhO1xuICAgICAgICAgICAgICBidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbi5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiA9IHNlYXJjaFNvdXJjZUpTT04ucmVwbGFjZSgnd2F6dWgtc3RhdGlzdGljcy0qJywgcGF0dGVybl9uYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh0aXRsZS5zdGFydHNXaXRoKCdXYXp1aCBBcHAgU3RhdGlzdGljcycpICYmIG5hbWUgIT09ICctJyAmJiBuYW1lICE9PSAnYWxsJyAmJiB2aXNTdGF0ZS5wYXJhbXMuZXhwcmVzc2lvbi5pbmNsdWRlcygncT0nKSkge1xuICAgICAgICAgICAgICBjb25zdCBleHByZXNzaW9uUmVnZXggPSAvcT0nXFwqJy9naTtcbiAgICAgICAgICAgICAgY29uc3QgX3Zpc1N0YXRlID0gYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmlzU3RhdGVCeU5vZGVcbiAgICAgICAgICAgICAgICA/IEpTT04ucGFyc2UoYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmlzU3RhdGVCeU5vZGUpXG4gICAgICAgICAgICAgICAgOiB2aXNTdGF0ZTtcbiAgICAgICAgICAgICAgcXVlcnkgKz0gX3Zpc1N0YXRlLnBhcmFtcy5leHByZXNzaW9uLnJlcGxhY2UoL3dhenVoLXN0YXRpc3RpY3MtXFwqL2csIHBhdHRlcm5fbmFtZSkucmVwbGFjZShleHByZXNzaW9uUmVnZXgsIGBxPVwibm9kZU5hbWUua2V5d29yZDoke25hbWV9IEFORCBhcGlOYW1lLmtleXdvcmQ6JHttYXN0ZXJfbm9kZX1cImApXG4gICAgICAgICAgICAgICAgLnJlcGxhY2UoXCJOT0RFX05BTUVcIiwgbmFtZSlcbiAgICAgICAgICAgIH0gZWxzZSBpZiAodGl0bGUuc3RhcnRzV2l0aCgnV2F6dWggQXBwIFN0YXRpc3RpY3MnKSkge1xuICAgICAgICAgICAgICBjb25zdCBleHByZXNzaW9uUmVnZXggPSAvcT0nXFwqJy9naVxuICAgICAgICAgICAgICBxdWVyeSArPSB2aXNTdGF0ZS5wYXJhbXMuZXhwcmVzc2lvbi5yZXBsYWNlKC93YXp1aC1zdGF0aXN0aWNzLVxcKi9nLCBwYXR0ZXJuX25hbWUpLnJlcGxhY2UoZXhwcmVzc2lvblJlZ2V4LCBgcT1cImFwaU5hbWUua2V5d29yZDoke21hc3Rlcl9ub2RlfVwiYClcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHF1ZXJ5ID0gdmlzU3RhdGUucGFyYW1zLmV4cHJlc3Npb247XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgdmlzU3RhdGUucGFyYW1zLmV4cHJlc3Npb24gPSBxdWVyeS5yZXBsYWNlKC8nL2csIFwiXFxcIlwiKTtcbiAgICAgICAgICBidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbi52aXNTdGF0ZSA9IEpTT04uc3RyaW5naWZ5KHZpc1N0YXRlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZpc0FycmF5LnB1c2goe1xuICAgICAgICAgIGF0dHJpYnV0ZXM6IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLFxuICAgICAgICAgIHR5cGU6IGVsZW1lbnQuX3R5cGUsXG4gICAgICAgICAgaWQ6IGVsZW1lbnQuX2lkLFxuICAgICAgICAgIF92ZXJzaW9uOiBidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbi52ZXJzaW9uXG4gICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdmlzQXJyYXk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3dhenVoLWVsYXN0aWM6YnVpbGRDbHVzdGVyVmlzdWFsaXphdGlvbnNSYXcnLFxuICAgICAgICBlcnJvci5tZXNzYWdlIHx8IGVycm9yXG4gICAgICApO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBjcmVhdGVzIGEgdmlzdWFsaXphdGlvbiBvZiBkYXRhIGluIHJlcVxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gdmlzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjcmVhdGVWaXMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3Q8eyBwYXR0ZXJuOiBzdHJpbmcsIHRhYjogc3RyaW5nIH0+LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKFxuICAgICAgICAoIXJlcXVlc3QucGFyYW1zLnRhYi5pbmNsdWRlcygnb3ZlcnZpZXctJykgJiZcbiAgICAgICAgICAhcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdhZ2VudHMtJykpXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdNaXNzaW5nIHBhcmFtZXRlcnMgY3JlYXRpbmcgdmlzdWFsaXphdGlvbnMnKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgdGFiUHJlZml4ID0gcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdvdmVydmlldycpXG4gICAgICAgID8gJ292ZXJ2aWV3J1xuICAgICAgICA6ICdhZ2VudHMnO1xuXG4gICAgICBjb25zdCB0YWJTcGxpdCA9IHJlcXVlc3QucGFyYW1zLnRhYi5zcGxpdCgnLScpO1xuICAgICAgY29uc3QgdGFiU3VmaXggPSB0YWJTcGxpdFsxXTtcblxuICAgICAgY29uc3QgZmlsZSA9XG4gICAgICAgIHRhYlByZWZpeCA9PT0gJ292ZXJ2aWV3J1xuICAgICAgICAgID8gT3ZlcnZpZXdWaXN1YWxpemF0aW9uc1t0YWJTdWZpeF1cbiAgICAgICAgICA6IEFnZW50c1Zpc3VhbGl6YXRpb25zW3RhYlN1Zml4XTtcbiAgICAgIGlmICghZmlsZSkge1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uubm90Rm91bmQoe2JvZHk6e21lc3NhZ2U6IGBWaXN1YWxpemF0aW9ucyBub3QgZm91bmQgZm9yICR7cmVxdWVzdC5wYXJhbXMudGFifWB9fSk7XG4gICAgICB9XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Y3JlYXRlVmlzJywgYCR7dGFiUHJlZml4fVske3RhYlN1Zml4fV0gd2l0aCBpbmRleCBwYXR0ZXJuICR7cmVxdWVzdC5wYXJhbXMucGF0dGVybn1gLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHJhdyA9IGF3YWl0IHRoaXMuYnVpbGRWaXN1YWxpemF0aW9uc1JhdyhcbiAgICAgICAgZmlsZSxcbiAgICAgICAgcmVxdWVzdC5wYXJhbXMucGF0dGVyblxuICAgICAgKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgYWNrbm93bGVkZ2U6IHRydWUsIHJhdzogcmF3IH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Y3JlYXRlVmlzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA0MDA3LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBjcmVhdGVzIGEgdmlzdWFsaXphdGlvbiBvZiBjbHVzdGVyXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSB2aXMgb2JqIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNyZWF0ZUNsdXN0ZXJWaXMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3Q8eyBwYXR0ZXJuOiBzdHJpbmcsIHRhYjogc3RyaW5nIH0sIHVua25vd24sIGFueT4sIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBpZiAoXG4gICAgICAgICFyZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuIHx8XG4gICAgICAgICFyZXF1ZXN0LnBhcmFtcy50YWIgfHxcbiAgICAgICAgIXJlcXVlc3QuYm9keSB8fFxuICAgICAgICAhcmVxdWVzdC5ib2R5Lm5vZGVzIHx8XG4gICAgICAgICFyZXF1ZXN0LmJvZHkubm9kZXMuYWZmZWN0ZWRfaXRlbXMgfHxcbiAgICAgICAgIXJlcXVlc3QuYm9keS5ub2Rlcy5uYW1lIHx8XG4gICAgICAgIChyZXF1ZXN0LnBhcmFtcy50YWIgJiYgIXJlcXVlc3QucGFyYW1zLnRhYi5pbmNsdWRlcygnY2x1c3Rlci0nKSlcbiAgICAgICkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ01pc3NpbmcgcGFyYW1ldGVycyBjcmVhdGluZyB2aXN1YWxpemF0aW9ucycpO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB0eXBlID0gcmVxdWVzdC5wYXJhbXMudGFiLnNwbGl0KCctJylbMV07XG5cbiAgICAgIGNvbnN0IGZpbGUgPSBDbHVzdGVyVmlzdWFsaXphdGlvbnNbdHlwZV07XG4gICAgICBjb25zdCBub2RlcyA9IHJlcXVlc3QuYm9keS5ub2Rlcy5hZmZlY3RlZF9pdGVtcztcbiAgICAgIGNvbnN0IG5hbWUgPSByZXF1ZXN0LmJvZHkubm9kZXMubmFtZTtcbiAgICAgIGNvbnN0IG1hc3Rlck5vZGUgPSByZXF1ZXN0LmJvZHkubm9kZXMubWFzdGVyX25vZGU7XG5cbiAgICAgIGNvbnN0IHsgaWQ6IHBhdHRlcm5JRCwgdGl0bGU6IHBhdHRlcm5OYW1lIH0gPSByZXF1ZXN0LmJvZHkucGF0dGVybjtcblxuICAgICAgY29uc3QgcmF3ID0gYXdhaXQgdGhpcy5idWlsZENsdXN0ZXJWaXN1YWxpemF0aW9uc1JhdyhcbiAgICAgICAgZmlsZSxcbiAgICAgICAgcGF0dGVybklELFxuICAgICAgICBub2RlcyxcbiAgICAgICAgbmFtZSxcbiAgICAgICAgbWFzdGVyTm9kZSxcbiAgICAgICAgcGF0dGVybk5hbWVcbiAgICAgICk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgYWNrbm93bGVkZ2U6IHRydWUsIHJhdzogcmF3IH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Y3JlYXRlQ2x1c3RlclZpcycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNDAwOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgY2hlY2tzIGlmIHRoZXJlIGlzIHNhbXBsZSBhbGVydHNcbiAgICogR0VUIC9lbGFzdGljL3NhbXBsZWFsZXJ0c1xuICAgKiBAcGFyYW0geyp9IGNvbnRleHRcbiAgICogQHBhcmFtIHsqfSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7Kn0gcmVzcG9uc2VcbiAgICoge2FsZXJ0czogWy4uLl19IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGhhdmVTYW1wbGVBbGVydHMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICAvLyBDaGVjayBpZiB3YXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4IGV4aXN0c1xuICAgICAgY29uc3QgcmVzdWx0cyA9IGF3YWl0IFByb21pc2UuYWxsKE9iamVjdC5rZXlzKFdBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUklFU19UWVBFX0FMRVJUUylcbiAgICAgICAgLm1hcCgoY2F0ZWdvcnkpID0+IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuZXhpc3RzKHtcbiAgICAgICAgICBpbmRleDogdGhpcy5idWlsZFNhbXBsZUluZGV4QnlDYXRlZ29yeShjYXRlZ29yeSlcbiAgICAgICAgfSkpKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgc2FtcGxlQWxlcnRzSW5zdGFsbGVkOiByZXN1bHRzLnNvbWUocmVzdWx0ID0+IHJlc3VsdC5ib2R5KSB9XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ1NhbXBsZSBBbGVydHMgY2F0ZWdvcnkgbm90IHZhbGlkJywgMTAwMCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG4gIC8qKlxuICAgKiBUaGlzIGNyZWF0ZXMgc2FtcGxlIGFsZXJ0cyBpbiB3YXp1aC1zYW1wbGUtYWxlcnRzXG4gICAqIEdFVCAvZWxhc3RpYy9zYW1wbGVhbGVydHMve2NhdGVnb3J5fVxuICAgKiBAcGFyYW0geyp9IGNvbnRleHRcbiAgICogQHBhcmFtIHsqfSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7Kn0gcmVzcG9uc2VcbiAgICoge2FsZXJ0czogWy4uLl19IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGhhdmVTYW1wbGVBbGVydHNPZkNhdGVnb3J5KGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0PHsgY2F0ZWdvcnk6IHN0cmluZyB9PiwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHNhbXBsZUFsZXJ0c0luZGV4ID0gdGhpcy5idWlsZFNhbXBsZUluZGV4QnlDYXRlZ29yeShyZXF1ZXN0LnBhcmFtcy5jYXRlZ29yeSk7XG4gICAgICAvLyBDaGVjayBpZiB3YXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4IGV4aXN0c1xuICAgICAgY29uc3QgZXhpc3RzU2FtcGxlSW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleFxuICAgICAgfSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCwgZXhpc3RzOiBleGlzdHNTYW1wbGVJbmRleC5ib2R5IH1cbiAgICAgIH0pXG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3dhenVoLWVsYXN0aWM6aGF2ZVNhbXBsZUFsZXJ0c09mQ2F0ZWdvcnknLFxuICAgICAgICBgRXJyb3IgY2hlY2tpbmcgaWYgdGhlcmUgYXJlIHNhbXBsZSBhbGVydHMgaW5kaWNlczogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWBcbiAgICAgICk7XG5cbiAgICAgIGNvbnN0IFtzdGF0dXNDb2RlLCBlcnJvck1lc3NhZ2VdID0gdGhpcy5nZXRFcnJvckRldGFpbHMoZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoYEVycm9yIGNoZWNraW5nIGlmIHRoZXJlIGFyZSBzYW1wbGUgYWxlcnRzIGluZGljZXM6ICR7ZXJyb3JNZXNzYWdlIHx8IGVycm9yfWAsIDEwMDAsIHN0YXR1c0NvZGUsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cbiAgLyoqXG4gICAqIFRoaXMgY3JlYXRlcyBzYW1wbGUgYWxlcnRzIGluIHdhenVoLXNhbXBsZS1hbGVydHNcbiAgICogUE9TVCAvZWxhc3RpYy9zYW1wbGVhbGVydHMve2NhdGVnb3J5fVxuICAgKiB7XG4gICAqICAgXCJtYW5hZ2VyXCI6IHtcbiAgICogICAgICBcIm5hbWVcIjogXCJtYW5hZ2VyX25hbWVcIlxuICAgKiAgICB9LFxuICAgKiAgICBjbHVzdGVyOiB7XG4gICAqICAgICAgbmFtZTogXCJteWNsdXN0ZXJcIixcbiAgICogICAgICBub2RlOiBcIm15bm9kZVwiXG4gICAqICAgIH1cbiAgICogfVxuICAgKiBAcGFyYW0geyp9IGNvbnRleHRcbiAgICogQHBhcmFtIHsqfSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7Kn0gcmVzcG9uc2VcbiAgICoge2luZGV4OiBzdHJpbmcsIGFsZXJ0czogWy4uLl0sIGNvdW50OiBudW1iZXJ9IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGNyZWF0ZVNhbXBsZUFsZXJ0cyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdDx7IGNhdGVnb3J5OiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIGNvbnN0IHNhbXBsZUFsZXJ0c0luZGV4ID0gdGhpcy5idWlsZFNhbXBsZUluZGV4QnlDYXRlZ29yeShyZXF1ZXN0LnBhcmFtcy5jYXRlZ29yeSk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gQ2hlY2sgaWYgdXNlciBoYXMgYWRtaW5pc3RyYXRvciByb2xlIGluIHRva2VuXG4gICAgICBjb25zdCB0b2tlbiA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei10b2tlbicpO1xuICAgICAgaWYgKCF0b2tlbikge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gdG9rZW4gcHJvdmlkZWQnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIGNvbnN0IGRlY29kZWRUb2tlbiA9IGp3dERlY29kZSh0b2tlbik7XG4gICAgICBpZiAoIWRlY29kZWRUb2tlbikge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gcGVybWlzc2lvbnMgaW4gdG9rZW4nLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIGlmICghZGVjb2RlZFRva2VuLnJiYWNfcm9sZXMgfHwgIWRlY29kZWRUb2tlbi5yYmFjX3JvbGVzLmluY2x1ZGVzKFdBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9JRCkpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIGFkbWluaXN0cmF0b3Igcm9sZScsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgLy8gQ2hlY2sgdGhlIHByb3ZpZGVkIHRva2VuIGlzIHZhbGlkXG4gICAgICBjb25zdCBhcGlIb3N0SUQgPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCAnd3otYXBpJyk7XG4gICAgICBpZiAoIWFwaUhvc3RJRCkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gQVBJIGlkIHByb3ZpZGVkJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICBjb25zdCByZXNwb25zZVRva2VuSXNXb3JraW5nID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdCgnR0VUJywgYC8vYCwge30sIHsgYXBpSG9zdElEIH0pO1xuICAgICAgaWYgKHJlc3BvbnNlVG9rZW5Jc1dvcmtpbmcuc3RhdHVzICE9PSAyMDApIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ1Rva2VuIGlzIG5vdCB2YWxpZCcsIDUwMCwgNTAwLCByZXNwb25zZSk7XG4gICAgICB9O1xuXG4gICAgICBjb25zdCBidWxrUHJlZml4ID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBpbmRleDoge1xuICAgICAgICAgIF9pbmRleDogc2FtcGxlQWxlcnRzSW5kZXhcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICBjb25zdCBhbGVydEdlbmVyYXRlUGFyYW1zID0gcmVxdWVzdC5ib2R5ICYmIHJlcXVlc3QuYm9keS5wYXJhbXMgfHwge307XG5cbiAgICAgIGNvbnN0IHNhbXBsZUFsZXJ0cyA9IFdBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUklFU19UWVBFX0FMRVJUU1tyZXF1ZXN0LnBhcmFtcy5jYXRlZ29yeV0ubWFwKCh0eXBlQWxlcnQpID0+IGdlbmVyYXRlQWxlcnRzKHsgLi4udHlwZUFsZXJ0LCAuLi5hbGVydEdlbmVyYXRlUGFyYW1zIH0sIHJlcXVlc3QuYm9keS5hbGVydHMgfHwgdHlwZUFsZXJ0LmFsZXJ0cyB8fCBXQVpVSF9TQU1QTEVfQUxFUlRTX0RFRkFVTFRfTlVNQkVSX0FMRVJUUykpLmZsYXQoKTtcbiAgICAgIGNvbnN0IGJ1bGsgPSBzYW1wbGVBbGVydHMubWFwKHNhbXBsZUFsZXJ0ID0+IGAke2J1bGtQcmVmaXh9XFxuJHtKU09OLnN0cmluZ2lmeShzYW1wbGVBbGVydCl9XFxuYCkuam9pbignJyk7XG5cbiAgICAgIC8vIEluZGV4IGFsZXJ0c1xuXG4gICAgICAvLyBDaGVjayBpZiB3YXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4IGV4aXN0c1xuICAgICAgY29uc3QgZXhpc3RzU2FtcGxlSW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleFxuICAgICAgfSk7XG4gICAgICBpZiAoIWV4aXN0c1NhbXBsZUluZGV4LmJvZHkpIHtcbiAgICAgICAgLy8gQ3JlYXRlIHdhenVoIHNhbXBsZSBhbGVydHMgaW5kZXhcblxuICAgICAgICBjb25zdCBjb25maWd1cmF0aW9uID0ge1xuICAgICAgICAgIHNldHRpbmdzOiB7XG4gICAgICAgICAgICBpbmRleDoge1xuICAgICAgICAgICAgICBudW1iZXJfb2Zfc2hhcmRzOiBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1NIQVJEUyxcbiAgICAgICAgICAgICAgbnVtYmVyX29mX3JlcGxpY2FzOiBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1JFUExJQ0FTXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuY3JlYXRlKHtcbiAgICAgICAgICBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXgsXG4gICAgICAgICAgYm9keTogY29uZmlndXJhdGlvblxuICAgICAgICB9KTtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgICAgYENyZWF0ZWQgJHtzYW1wbGVBbGVydHNJbmRleH0gaW5kZXhgLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgY29udGV4dC5jb3JlLm9wZW5zZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuYnVsayh7XG4gICAgICAgIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCxcbiAgICAgICAgYm9keTogYnVsa1xuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgIGBBZGRlZCBzYW1wbGUgYWxlcnRzIHRvICR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4YCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4LCBhbGVydENvdW50OiBzYW1wbGVBbGVydHMubGVuZ3RoIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgIGBFcnJvciBhZGRpbmcgc2FtcGxlIGFsZXJ0cyB0byAke3NhbXBsZUFsZXJ0c0luZGV4fSBpbmRleDogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWBcbiAgICAgICk7XG4gICAgICBcbiAgICAgIGNvbnN0IFtzdGF0dXNDb2RlLCBlcnJvck1lc3NhZ2VdID0gdGhpcy5nZXRFcnJvckRldGFpbHMoZXJyb3IpO1xuICAgICAgXG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvck1lc3NhZ2UgfHwgZXJyb3IsIDEwMDAsIHN0YXR1c0NvZGUsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cbiAgLyoqXG4gICAqIFRoaXMgZGVsZXRlcyBzYW1wbGUgYWxlcnRzXG4gICAqIEBwYXJhbSB7Kn0gY29udGV4dFxuICAgKiBAcGFyYW0geyp9IHJlcXVlc3RcbiAgICogQHBhcmFtIHsqfSByZXNwb25zZVxuICAgKiB7cmVzdWx0OiBcImRlbGV0ZWRcIiwgaW5kZXg6IHN0cmluZ30gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZGVsZXRlU2FtcGxlQWxlcnRzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0PHsgY2F0ZWdvcnk6IHN0cmluZyB9PiwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgLy8gRGVsZXRlIFdhenVoIHNhbXBsZSBhbGVydCBpbmRleFxuXG4gICAgY29uc3Qgc2FtcGxlQWxlcnRzSW5kZXggPSB0aGlzLmJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5KHJlcXVlc3QucGFyYW1zLmNhdGVnb3J5KTtcblxuICAgIHRyeSB7XG4gICAgICAvLyBDaGVjayBpZiB1c2VyIGhhcyBhZG1pbmlzdHJhdG9yIHJvbGUgaW4gdG9rZW5cbiAgICAgIGNvbnN0IHRva2VuID0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LXRva2VuJyk7XG4gICAgICBpZiAoIXRva2VuKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyB0b2tlbiBwcm92aWRlZCcsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgY29uc3QgZGVjb2RlZFRva2VuID0gand0RGVjb2RlKHRva2VuKTtcbiAgICAgIGlmICghZGVjb2RlZFRva2VuKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBwZXJtaXNzaW9ucyBpbiB0b2tlbicsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgaWYgKCFkZWNvZGVkVG9rZW4ucmJhY19yb2xlcyB8fCAhZGVjb2RlZFRva2VuLnJiYWNfcm9sZXMuaW5jbHVkZXMoV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lEKSkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gYWRtaW5pc3RyYXRvciByb2xlJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICAvLyBDaGVjayB0aGUgcHJvdmlkZWQgdG9rZW4gaXMgdmFsaWRcbiAgICAgIGNvbnN0IGFwaUhvc3RJRCA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei1hcGknKTtcbiAgICAgIGlmICghYXBpSG9zdElEKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBBUEkgaWQgcHJvdmlkZWQnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIGNvbnN0IHJlc3BvbnNlVG9rZW5Jc1dvcmtpbmcgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KCdHRVQnLCBgLy9gLCB7fSwgeyBhcGlIb3N0SUQgfSk7XG4gICAgICBpZiAocmVzcG9uc2VUb2tlbklzV29ya2luZy5zdGF0dXMgIT09IDIwMCkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnVG9rZW4gaXMgbm90IHZhbGlkJywgNTAwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICAgIH07XG5cbiAgICAgIC8vIENoZWNrIGlmIFdhenVoIHNhbXBsZSBhbGVydHMgaW5kZXggZXhpc3RzXG4gICAgICBjb25zdCBleGlzdHNTYW1wbGVJbmRleCA9IGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuZXhpc3RzKHtcbiAgICAgICAgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4XG4gICAgICB9KTtcbiAgICAgIGlmIChleGlzdHNTYW1wbGVJbmRleC5ib2R5KSB7XG4gICAgICAgIC8vIERlbGV0ZSBXYXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4XG4gICAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuZGVsZXRlKHsgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4IH0pO1xuICAgICAgICBsb2coXG4gICAgICAgICAgJ3dhenVoLWVsYXN0aWM6ZGVsZXRlU2FtcGxlQWxlcnRzJyxcbiAgICAgICAgICBgRGVsZXRlZCAke3NhbXBsZUFsZXJ0c0luZGV4fSBpbmRleGAsXG4gICAgICAgICAgJ2RlYnVnJ1xuICAgICAgICApO1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHsgcmVzdWx0OiAnZGVsZXRlZCcsIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoYCR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4IGRvZXNuJ3QgZXhpc3RgLCAxMDAwLCA1MDAsIHJlc3BvbnNlKVxuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmRlbGV0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgIGBFcnJvciBkZWxldGluZyBzYW1wbGUgYWxlcnRzIG9mICR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4OiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICAgKTtcbiAgICAgIGNvbnN0IFtzdGF0dXNDb2RlLCBlcnJvck1lc3NhZ2VdID0gdGhpcy5nZXRFcnJvckRldGFpbHMoZXJyb3IpO1xuXG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvck1lc3NhZ2UgfHwgZXJyb3IsIDEwMDAsIHN0YXR1c0NvZGUsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICBhc3luYyBhbGVydHMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBkYXRhID0gYXdhaXQgY29udGV4dC5jb3JlLm9wZW5zZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuc2VhcmNoKHJlcXVlc3QuYm9keSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiBkYXRhLmJvZHlcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6YWxlcnRzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA0MDEwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvLyBDaGVjayBpZiB0aGVyZSBhcmUgaW5kaWNlcyBmb3IgU3RhdGlzdGljc1xuICBhc3luYyBleGlzdFN0YXRpc3RpY3NJbmRpY2VzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgICAgY29uc3Qgc3RhdGlzdGljc1BhdHRlcm4gPSBgJHtjb25maWdbJ2Nyb24ucHJlZml4J10gfHwgJ3dhenVoJ30tJHtjb25maWdbJ2Nyb24uc3RhdGlzdGljcy5pbmRleC5uYW1lJ10gfHwgJ3N0YXRpc3RpY3MnfSpgOyAvL1RPRE86IHJlcGxhY2UgYnkgZGVmYXVsdCBhcyBjb25zdGFudHMgaW5zdGVhZCBoYXJkY29kZWQgKCd3YXp1aCcgYW5kICdzdGF0aXN0aWNzJylcbiAgICAgIGNvbnN0IGV4aXN0SW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzdGF0aXN0aWNzUGF0dGVybixcbiAgICAgICAgYWxsb3dfbm9faW5kaWNlczogZmFsc2VcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogZXhpc3RJbmRleC5ib2R5XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmV4aXN0c1N0YXRpc3RpY3NJbmRpY2VzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAxMDAwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICBnZXRFcnJvckRldGFpbHMoZXJyb3Ipe1xuICAgIGNvbnN0IHN0YXR1c0NvZGUgPSBlcnJvcj8ubWV0YT8uc3RhdHVzQ29kZSB8fCA1MDA7XG4gICAgbGV0IGVycm9yTWVzc2FnZSA9IGVycm9yLm1lc3NhZ2U7XG5cbiAgICBpZihzdGF0dXNDb2RlID09PSA0MDMpe1xuICAgICAgZXJyb3JNZXNzYWdlID0gZXJyb3I/Lm1ldGE/LmJvZHk/LmVycm9yPy5yZWFzb24gfHwgJ1Blcm1pc3Npb24gZGVuaWVkJztcbiAgICB9XG5cbiAgICByZXR1cm4gW3N0YXR1c0NvZGUsIGVycm9yTWVzc2FnZV07XG4gIH1cbn1cbiJdfQ==