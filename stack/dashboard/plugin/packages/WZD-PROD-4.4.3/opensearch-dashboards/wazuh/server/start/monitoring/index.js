"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jobMonitoringRun = jobMonitoringRun;

var _nodeCron = _interopRequireDefault(require("node-cron"));

var _logger = require("../../lib/logger");

var _monitoringTemplate = require("../../integration-files/monitoring-template");

var _getConfiguration = require("../../lib/get-configuration");

var _parseCron = require("../../lib/parse-cron");

var _indexDate = require("../../lib/index-date");

var _buildIndexSettings = require("../../lib/build-index-settings");

var _wazuhHosts = require("../../controllers/wazuh-hosts");

var _constants = require("../../../common/constants");

var _tryCatchForIndexPermissionError = require("../tryCatchForIndexPermissionError");

var _utils = require("../../../common/utils");

var _settings = require("../../../common/services/settings");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
 * Wazuh app - Module for agent info fetching functions
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const blueWazuh = '\u001b[34mwazuh\u001b[39m';
const monitoringErrorLogColors = [blueWazuh, 'monitoring', 'error'];
const wazuhHostController = new _wazuhHosts.WazuhHostsCtrl();
let MONITORING_ENABLED, MONITORING_FREQUENCY, MONITORING_CRON_FREQ, MONITORING_CREATION, MONITORING_INDEX_PATTERN, MONITORING_INDEX_PREFIX; // Utils functions

/**
 * Get the setting value from the configuration
 * @param setting
 * @param configuration
 * @param defaultValue
 */

function getAppConfigurationSetting(setting, configuration, defaultValue) {
  return typeof configuration[setting] !== 'undefined' ? configuration[setting] : defaultValue;
}

;
/**
 * Set the monitoring variables
 * @param context
 */

function initMonitoringConfiguration(context) {
  try {
    const appConfig = (0, _getConfiguration.getConfiguration)();
    MONITORING_ENABLED = appConfig && typeof appConfig['wazuh.monitoring.enabled'] !== 'undefined' ? appConfig['wazuh.monitoring.enabled'] && appConfig['wazuh.monitoring.enabled'] !== 'worker' : (0, _settings.getSettingDefaultValue)('wazuh.monitoring.enabled');
    MONITORING_FREQUENCY = getAppConfigurationSetting('wazuh.monitoring.frequency', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.frequency'));
    MONITORING_CRON_FREQ = (0, _parseCron.parseCron)(MONITORING_FREQUENCY);
    MONITORING_CREATION = getAppConfigurationSetting('wazuh.monitoring.creation', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.creation'));
    MONITORING_INDEX_PATTERN = getAppConfigurationSetting('wazuh.monitoring.pattern', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern'));
    const lastCharIndexPattern = MONITORING_INDEX_PATTERN[MONITORING_INDEX_PATTERN.length - 1];

    if (lastCharIndexPattern !== '*') {
      MONITORING_INDEX_PATTERN += '*';
    }

    ;
    MONITORING_INDEX_PREFIX = MONITORING_INDEX_PATTERN.slice(0, MONITORING_INDEX_PATTERN.length - 1);
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.enabled: ${MONITORING_ENABLED}`, 'debug');
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.frequency: ${MONITORING_FREQUENCY} (${MONITORING_CRON_FREQ})`, 'debug');
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.pattern: ${MONITORING_INDEX_PATTERN} (index prefix: ${MONITORING_INDEX_PREFIX})`, 'debug');
  } catch (error) {
    const errorMessage = error.message || error;
    (0, _logger.log)('monitoring:initMonitoringConfiguration', errorMessage);
    context.wazuh.logger.error(errorMessage);
  }
}

;
/**
 * Main. First execution when installing / loading App.
 * @param context
 */

async function init(context) {
  try {
    if (MONITORING_ENABLED) {
      await checkTemplate(context);
    }

    ;
  } catch (error) {
    const errorMessage = error.message || error;
    (0, _logger.log)('monitoring:init', error.message || error);
    context.wazuh.logger.error(errorMessage);
  }
}
/**
 * Verify wazuh-agent template
 */


async function checkTemplate(context) {
  try {
    (0, _logger.log)('monitoring:checkTemplate', 'Updating the monitoring template', 'debug');

    try {
      // Check if the template already exists
      const currentTemplate = await context.core.opensearch.client.asInternalUser.indices.getTemplate({
        name: _constants.WAZUH_MONITORING_TEMPLATE_NAME
      }); // Copy already created index patterns

      _monitoringTemplate.monitoringTemplate.index_patterns = currentTemplate.body[_constants.WAZUH_MONITORING_TEMPLATE_NAME].index_patterns;
    } catch (error) {
      // Init with the default index pattern
      _monitoringTemplate.monitoringTemplate.index_patterns = [(0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern')];
    } // Check if the user is using a custom pattern and add it to the template if it does


    if (!_monitoringTemplate.monitoringTemplate.index_patterns.includes(MONITORING_INDEX_PATTERN)) {
      _monitoringTemplate.monitoringTemplate.index_patterns.push(MONITORING_INDEX_PATTERN);
    }

    ; // Update the monitoring template

    await context.core.opensearch.client.asInternalUser.indices.putTemplate({
      name: _constants.WAZUH_MONITORING_TEMPLATE_NAME,
      body: _monitoringTemplate.monitoringTemplate
    });
    (0, _logger.log)('monitoring:checkTemplate', 'Updated the monitoring template', 'debug');
  } catch (error) {
    const errorMessage = `Something went wrong updating the monitoring template ${error.message || error}`;
    (0, _logger.log)('monitoring:checkTemplate', errorMessage);
    context.wazuh.logger.error(monitoringErrorLogColors, errorMessage);
    throw error;
  }
}
/**
 * Save agent status into elasticsearch, create index and/or insert document
 * @param {*} context
 * @param {*} data
 */


async function insertMonitoringDataElasticsearch(context, data) {
  const monitoringIndexName = MONITORING_INDEX_PREFIX + (0, _indexDate.indexDate)(MONITORING_CREATION);

  if (!MONITORING_ENABLED) {
    return;
  }

  ;

  try {
    await (0, _tryCatchForIndexPermissionError.tryCatchForIndexPermissionError)(monitoringIndexName)(async () => {
      const exists = await context.core.opensearch.client.asInternalUser.indices.exists({
        index: monitoringIndexName
      });

      if (!exists.body) {
        await createIndex(context, monitoringIndexName);
      }

      ; // Update the index configuration

      const appConfig = (0, _getConfiguration.getConfiguration)();
      const indexConfiguration = (0, _buildIndexSettings.buildIndexSettings)(appConfig, 'wazuh.monitoring', (0, _settings.getSettingDefaultValue)('wazuh.monitoring.shards')); // To update the index settings with this client is required close the index, update the settings and open it
      // Number of shards is not dynamic so delete that setting if it's given

      delete indexConfiguration.settings.index.number_of_shards;
      await context.core.opensearch.client.asInternalUser.indices.putSettings({
        index: monitoringIndexName,
        body: indexConfiguration
      }); // Insert data to the monitoring index

      await insertDataToIndex(context, monitoringIndexName, data);
    })();
  } catch (error) {
    (0, _logger.log)('monitoring:insertMonitoringDataElasticsearch', error.message || error);
    context.wazuh.logger.error(error.message);
  }
}
/**
 * Inserting one document per agent into Elastic. Bulk.
 * @param {*} context Endpoint
 * @param {String} indexName The name for the index (e.g. daily: wazuh-monitoring-YYYY.MM.DD)
 * @param {*} data
 */


async function insertDataToIndex(context, indexName, data) {
  const {
    agents,
    apiHost
  } = data;

  try {
    if (agents.length > 0) {
      (0, _logger.log)('monitoring:insertDataToIndex', `Bulk data to index ${indexName} for ${agents.length} agents`, 'debug');
      const bodyBulk = agents.map(agent => {
        const agentInfo = { ...agent
        };
        agentInfo['timestamp'] = new Date(Date.now()).toISOString();
        agentInfo.host = agent.manager;
        agentInfo.cluster = {
          name: apiHost.clusterName ? apiHost.clusterName : 'disabled'
        };
        return `{ "index":  { "_index": "${indexName}" } }\n${JSON.stringify(agentInfo)}\n`;
      }).join('');
      await context.core.opensearch.client.asInternalUser.bulk({
        index: indexName,
        body: bodyBulk
      });
      (0, _logger.log)('monitoring:insertDataToIndex', `Bulk data to index ${indexName} for ${agents.length} agents completed`, 'debug');
    }
  } catch (error) {
    (0, _logger.log)('monitoring:insertDataToIndex', `Error inserting agent data into elasticsearch. Bulk request failed due to ${error.message || error}`);
  }
}
/**
 * Create the wazuh-monitoring index
 * @param {*} context context
 * @param {String} indexName The name for the index (e.g. daily: wazuh-monitoring-YYYY.MM.DD)
 */


async function createIndex(context, indexName) {
  try {
    if (!MONITORING_ENABLED) return;
    const appConfig = (0, _getConfiguration.getConfiguration)();
    const IndexConfiguration = {
      settings: {
        index: {
          number_of_shards: getAppConfigurationSetting('wazuh.monitoring.shards', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.shards')),
          number_of_replicas: getAppConfigurationSetting('wazuh.monitoring.replicas', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.replicas'))
        }
      }
    };
    await context.core.opensearch.client.asInternalUser.indices.create({
      index: indexName,
      body: IndexConfiguration
    });
    (0, _logger.log)('monitoring:createIndex', `Successfully created new index: ${indexName}`, 'debug');
  } catch (error) {
    const errorMessage = `Could not create ${indexName} index on elasticsearch due to ${error.message || error}`;
    (0, _logger.log)('monitoring:createIndex', errorMessage);
    context.wazuh.logger.error(errorMessage);
  }
}
/**
* Wait until Kibana server is ready
*/


async function checkPluginPlatformStatus(context) {
  try {
    (0, _logger.log)('monitoring:checkPluginPlatformStatus', 'Waiting for Kibana and Elasticsearch servers to be ready...', 'debug');
    await checkElasticsearchServer(context);
    await init(context);
    return;
  } catch (error) {
    (0, _logger.log)('monitoring:checkPluginPlatformStatus', error.mesage || error);

    try {
      await (0, _utils.delayAsPromise)(3000);
      await checkPluginPlatformStatus(context);
    } catch (error) {}

    ;
  }
}
/**
 * Check Elasticsearch Server status and Kibana index presence
 */


async function checkElasticsearchServer(context) {
  try {
    const data = await context.core.opensearch.client.asInternalUser.indices.exists({
      index: context.server.config.opensearchDashboards.index
    });
    return data.body; // TODO: check if Elasticsearch can receive requests
    // if (data) {
    //   const pluginsData = await this.server.plugins.elasticsearch.waitUntilReady();
    //   return pluginsData;
    // }

    return Promise.reject(data);
  } catch (error) {
    (0, _logger.log)('monitoring:checkElasticsearchServer', error.message || error);
    return Promise.reject(error);
  }
}

const fakeResponseEndpoint = {
  ok: body => body,
  custom: body => body
};
/**
 * Get API configuration from elastic and callback to loadCredentials
 */

async function getHostsConfiguration() {
  try {
    const hosts = await wazuhHostController.getHostsEntries(false, false, fakeResponseEndpoint);

    if (hosts.body.length) {
      return hosts.body;
    }

    ;
    (0, _logger.log)('monitoring:getConfig', 'There are no Wazuh API entries yet', 'debug');
    return Promise.reject({
      error: 'no credentials',
      error_code: 1
    });
  } catch (error) {
    (0, _logger.log)('monitoring:getHostsConfiguration', error.message || error);
    return Promise.reject({
      error: 'no wazuh hosts',
      error_code: 2
    });
  }
}
/**
   * Task used by the cron job.
   */


async function cronTask(context) {
  try {
    const templateMonitoring = await context.core.opensearch.client.asInternalUser.indices.getTemplate({
      name: _constants.WAZUH_MONITORING_TEMPLATE_NAME
    });
    const apiHosts = await getHostsConfiguration();
    const apiHostsUnique = (apiHosts || []).filter((apiHost, index, self) => index === self.findIndex(t => t.user === apiHost.user && t.password === apiHost.password && t.url === apiHost.url && t.port === apiHost.port));

    for (let apiHost of apiHostsUnique) {
      try {
        const {
          agents,
          apiHost: host
        } = await getApiInfo(context, apiHost);
        await insertMonitoringDataElasticsearch(context, {
          agents,
          apiHost: host
        });
      } catch (error) {}

      ;
    }
  } catch (error) {
    // Retry to call itself again if Kibana index is not ready yet
    // try {
    //   if (
    //     this.wzWrapper.buildingKibanaIndex ||
    //     ((error || {}).status === 404 &&
    //       (error || {}).displayName === 'NotFound')
    //   ) {
    //     await delayAsPromise(1000);
    //     return cronTask(context);
    //   }
    // } catch (error) {} //eslint-disable-line
    (0, _logger.log)('monitoring:cronTask', error.message || error);
    context.wazuh.logger.error(error.message || error);
  }
}
/**
 * Get API and agents info
 * @param context
 * @param apiHost
 */


async function getApiInfo(context, apiHost) {
  try {
    (0, _logger.log)('monitoring:getApiInfo', `Getting API info for ${apiHost.id}`, 'debug');
    const responseIsCluster = await context.wazuh.api.client.asInternalUser.request('GET', '/cluster/status', {}, {
      apiHostID: apiHost.id
    });
    const isCluster = (((responseIsCluster || {}).data || {}).data || {}).enabled === 'yes';

    if (isCluster) {
      const responseClusterInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
        apiHostID: apiHost.id
      });
      apiHost.clusterName = responseClusterInfo.data.data.affected_items[0].cluster;
    }

    ;
    const agents = await fetchAllAgentsFromApiHost(context, apiHost);
    return {
      agents,
      apiHost
    };
  } catch (error) {
    (0, _logger.log)('monitoring:getApiInfo', error.message || error);
    throw error;
  }
}

;
/**
 * Fetch all agents for the API provided
 * @param context
 * @param apiHost
 */

async function fetchAllAgentsFromApiHost(context, apiHost) {
  let agents = [];

  try {
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `Getting all agents from ApiID: ${apiHost.id}`, 'debug');
    const responseAgentsCount = await context.wazuh.api.client.asInternalUser.request('GET', '/agents', {
      params: {
        offset: 0,
        limit: 1,
        q: 'id!=000'
      }
    }, {
      apiHostID: apiHost.id
    });
    const agentsCount = responseAgentsCount.data.data.total_affected_items;
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}, Agent count: ${agentsCount}`, 'debug');
    let payload = {
      offset: 0,
      limit: 500,
      q: 'id!=000'
    };

    while (agents.length < agentsCount && payload.offset < agentsCount) {
      try {
        /*
        TODO: Improve the performance of request with:
          - Reduce the number of requests to the Wazuh API
          - Reduce (if possible) the quantity of data to index by document
         Requirements:
          - Research about the neccesary data to index.
         How to do:
          - Wazuh API request:
            - select the required data to retrieve depending on is required to index (using the `select` query param)
            - increase the limit of results to retrieve (currently, the requests use the recommended value: 500).
              See the allowed values. This depends on the selected data because the response could fail if contains a lot of data
        */
        const responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: payload
        }, {
          apiHostID: apiHost.id
        });
        agents = [...agents, ...responseAgents.data.data.affected_items];
        payload.offset += payload.limit;
      } catch (error) {
        (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}, Error request with offset/limit ${payload.offset}/${payload.limit}: ${error.message || error}`);
      }
    }

    return agents;
  } catch (error) {
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}. Error: ${error.message || error}`);
    throw error;
  }
}

;
/**
 * Start the cron job
 */

async function jobMonitoringRun(context) {
  // Init the monitoring variables
  initMonitoringConfiguration(context); // Check Kibana index and if it is prepared, start the initialization of Wazuh App.

  await checkPluginPlatformStatus(context); // // Run the cron job only it it's enabled

  if (MONITORING_ENABLED) {
    cronTask(context);

    _nodeCron.default.schedule(MONITORING_CRON_FREQ, () => cronTask(context));
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbImJsdWVXYXp1aCIsIm1vbml0b3JpbmdFcnJvckxvZ0NvbG9ycyIsIndhenVoSG9zdENvbnRyb2xsZXIiLCJXYXp1aEhvc3RzQ3RybCIsIk1PTklUT1JJTkdfRU5BQkxFRCIsIk1PTklUT1JJTkdfRlJFUVVFTkNZIiwiTU9OSVRPUklOR19DUk9OX0ZSRVEiLCJNT05JVE9SSU5HX0NSRUFUSU9OIiwiTU9OSVRPUklOR19JTkRFWF9QQVRURVJOIiwiTU9OSVRPUklOR19JTkRFWF9QUkVGSVgiLCJnZXRBcHBDb25maWd1cmF0aW9uU2V0dGluZyIsInNldHRpbmciLCJjb25maWd1cmF0aW9uIiwiZGVmYXVsdFZhbHVlIiwiaW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uIiwiY29udGV4dCIsImFwcENvbmZpZyIsImxhc3RDaGFySW5kZXhQYXR0ZXJuIiwibGVuZ3RoIiwic2xpY2UiLCJlcnJvciIsImVycm9yTWVzc2FnZSIsIm1lc3NhZ2UiLCJ3YXp1aCIsImxvZ2dlciIsImluaXQiLCJjaGVja1RlbXBsYXRlIiwiY3VycmVudFRlbXBsYXRlIiwiY29yZSIsIm9wZW5zZWFyY2giLCJjbGllbnQiLCJhc0ludGVybmFsVXNlciIsImluZGljZXMiLCJnZXRUZW1wbGF0ZSIsIm5hbWUiLCJXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUiLCJtb25pdG9yaW5nVGVtcGxhdGUiLCJpbmRleF9wYXR0ZXJucyIsImJvZHkiLCJpbmNsdWRlcyIsInB1c2giLCJwdXRUZW1wbGF0ZSIsImluc2VydE1vbml0b3JpbmdEYXRhRWxhc3RpY3NlYXJjaCIsImRhdGEiLCJtb25pdG9yaW5nSW5kZXhOYW1lIiwiZXhpc3RzIiwiaW5kZXgiLCJjcmVhdGVJbmRleCIsImluZGV4Q29uZmlndXJhdGlvbiIsInNldHRpbmdzIiwibnVtYmVyX29mX3NoYXJkcyIsInB1dFNldHRpbmdzIiwiaW5zZXJ0RGF0YVRvSW5kZXgiLCJpbmRleE5hbWUiLCJhZ2VudHMiLCJhcGlIb3N0IiwiYm9keUJ1bGsiLCJtYXAiLCJhZ2VudCIsImFnZW50SW5mbyIsIkRhdGUiLCJub3ciLCJ0b0lTT1N0cmluZyIsImhvc3QiLCJtYW5hZ2VyIiwiY2x1c3RlciIsImNsdXN0ZXJOYW1lIiwiSlNPTiIsInN0cmluZ2lmeSIsImpvaW4iLCJidWxrIiwiSW5kZXhDb25maWd1cmF0aW9uIiwibnVtYmVyX29mX3JlcGxpY2FzIiwiY3JlYXRlIiwiY2hlY2tQbHVnaW5QbGF0Zm9ybVN0YXR1cyIsImNoZWNrRWxhc3RpY3NlYXJjaFNlcnZlciIsIm1lc2FnZSIsInNlcnZlciIsImNvbmZpZyIsIm9wZW5zZWFyY2hEYXNoYm9hcmRzIiwiUHJvbWlzZSIsInJlamVjdCIsImZha2VSZXNwb25zZUVuZHBvaW50Iiwib2siLCJjdXN0b20iLCJnZXRIb3N0c0NvbmZpZ3VyYXRpb24iLCJob3N0cyIsImdldEhvc3RzRW50cmllcyIsImVycm9yX2NvZGUiLCJjcm9uVGFzayIsInRlbXBsYXRlTW9uaXRvcmluZyIsImFwaUhvc3RzIiwiYXBpSG9zdHNVbmlxdWUiLCJmaWx0ZXIiLCJzZWxmIiwiZmluZEluZGV4IiwidCIsInVzZXIiLCJwYXNzd29yZCIsInVybCIsInBvcnQiLCJnZXRBcGlJbmZvIiwiaWQiLCJyZXNwb25zZUlzQ2x1c3RlciIsImFwaSIsInJlcXVlc3QiLCJhcGlIb3N0SUQiLCJpc0NsdXN0ZXIiLCJlbmFibGVkIiwicmVzcG9uc2VDbHVzdGVySW5mbyIsImFmZmVjdGVkX2l0ZW1zIiwiZmV0Y2hBbGxBZ2VudHNGcm9tQXBpSG9zdCIsInJlc3BvbnNlQWdlbnRzQ291bnQiLCJwYXJhbXMiLCJvZmZzZXQiLCJsaW1pdCIsInEiLCJhZ2VudHNDb3VudCIsInRvdGFsX2FmZmVjdGVkX2l0ZW1zIiwicGF5bG9hZCIsInJlc3BvbnNlQWdlbnRzIiwiam9iTW9uaXRvcmluZ1J1biIsImNyb24iLCJzY2hlZHVsZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQVdBOztBQUNBOztBQUNBOztB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M0IsQ0FGOEMsQ0FHOUM7O0FBQ0EsUUFBTTJELHlCQUF5QixDQUFDM0QsT0FBRCxDQUEvQixDQUo4QyxDQUs5Qzs7QUFDQSxNQUFJWCxrQkFBSixFQUF3QjtBQUN0QnFGLElBQUFBLFFBQVEsQ0FBQzFFLE9BQUQsQ0FBUjs7QUFDQTJHLHNCQUFLQyxRQUFMLENBQWNySCxvQkFBZCxFQUFvQyxNQUFNbUYsUUFBUSxDQUFDMUUsT0FBRCxDQUFsRDtBQUNEO0FBQ0YiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBhZ2VudCBpbmZvIGZldGNoaW5nIGZ1bmN0aW9uc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCBjcm9uIGZyb20gJ25vZGUtY3Jvbic7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuLi8uLi9saWIvbG9nZ2VyJztcbmltcG9ydCB7IG1vbml0b3JpbmdUZW1wbGF0ZSB9IGZyb20gJy4uLy4uL2ludGVncmF0aW9uLWZpbGVzL21vbml0b3JpbmctdGVtcGxhdGUnO1xuaW1wb3J0IHsgZ2V0Q29uZmlndXJhdGlvbiB9IGZyb20gJy4uLy4uL2xpYi9nZXQtY29uZmlndXJhdGlvbic7XG5pbXBvcnQgeyBwYXJzZUNyb24gfSBmcm9tICcuLi8uLi9saWIvcGFyc2UtY3Jvbic7XG5pbXBvcnQgeyBpbmRleERhdGUgfSBmcm9tICcuLi8uLi9saWIvaW5kZXgtZGF0ZSc7XG5pbXBvcnQgeyBidWlsZEluZGV4U2V0dGluZ3MgfSBmcm9tICcuLi8uLi9saWIvYnVpbGQtaW5kZXgtc2V0dGluZ3MnO1xuaW1wb3J0IHsgV2F6dWhIb3N0c0N0cmwgfSBmcm9tICcuLi8uLi9jb250cm9sbGVycy93YXp1aC1ob3N0cyc7XG5pbXBvcnQge1xuICBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUsXG59IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgdHJ5Q2F0Y2hGb3JJbmRleFBlcm1pc3Npb25FcnJvciB9IGZyb20gJy4uL3RyeUNhdGNoRm9ySW5kZXhQZXJtaXNzaW9uRXJyb3InO1xuaW1wb3J0IHsgZGVsYXlBc1Byb21pc2UgfSBmcm9tICcuLi8uLi8uLi9jb21tb24vdXRpbHMnO1xuaW1wb3J0IHsgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncyc7XG5cbmNvbnN0IGJsdWVXYXp1aCA9ICdcXHUwMDFiWzM0bXdhenVoXFx1MDAxYlszOW0nO1xuY29uc3QgbW9uaXRvcmluZ0Vycm9yTG9nQ29sb3JzID0gW2JsdWVXYXp1aCwgJ21vbml0b3JpbmcnLCAnZXJyb3InXTtcbmNvbnN0IHdhenVoSG9zdENvbnRyb2xsZXIgPSBuZXcgV2F6dWhIb3N0c0N0cmwoKTtcblxubGV0IE1PTklUT1JJTkdfRU5BQkxFRCwgTU9OSVRPUklOR19GUkVRVUVOQ1ksIE1PTklUT1JJTkdfQ1JPTl9GUkVRLCBNT05JVE9SSU5HX0NSRUFUSU9OLCBNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4sIE1PTklUT1JJTkdfSU5ERVhfUFJFRklYO1xuXG4vLyBVdGlscyBmdW5jdGlvbnNcbi8qKlxuICogR2V0IHRoZSBzZXR0aW5nIHZhbHVlIGZyb20gdGhlIGNvbmZpZ3VyYXRpb25cbiAqIEBwYXJhbSBzZXR0aW5nXG4gKiBAcGFyYW0gY29uZmlndXJhdGlvblxuICogQHBhcmFtIGRlZmF1bHRWYWx1ZVxuICovXG5mdW5jdGlvbiBnZXRBcHBDb25maWd1cmF0aW9uU2V0dGluZyhzZXR0aW5nOiBzdHJpbmcsIGNvbmZpZ3VyYXRpb246IGFueSwgZGVmYXVsdFZhbHVlOiBhbnkpIHtcbiAgcmV0dXJuIHR5cGVvZiBjb25maWd1cmF0aW9uW3NldHRpbmddICE9PSAndW5kZWZpbmVkJyA/IGNvbmZpZ3VyYXRpb25bc2V0dGluZ10gOiBkZWZhdWx0VmFsdWU7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgbW9uaXRvcmluZyB2YXJpYWJsZXNcbiAqIEBwYXJhbSBjb250ZXh0XG4gKi9cbmZ1bmN0aW9uIGluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbihjb250ZXh0KSB7XG4gIHRyeSB7XG4gICAgY29uc3QgYXBwQ29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgIE1PTklUT1JJTkdfRU5BQkxFRCA9IGFwcENvbmZpZyAmJiB0eXBlb2YgYXBwQ29uZmlnWyd3YXp1aC5tb25pdG9yaW5nLmVuYWJsZWQnXSAhPT0gJ3VuZGVmaW5lZCdcbiAgICAgID8gYXBwQ29uZmlnWyd3YXp1aC5tb25pdG9yaW5nLmVuYWJsZWQnXSAmJlxuICAgICAgYXBwQ29uZmlnWyd3YXp1aC5tb25pdG9yaW5nLmVuYWJsZWQnXSAhPT0gJ3dvcmtlcidcbiAgICAgIDogZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgnd2F6dWgubW9uaXRvcmluZy5lbmFibGVkJyk7XG4gICAgTU9OSVRPUklOR19GUkVRVUVOQ1kgPSBnZXRBcHBDb25maWd1cmF0aW9uU2V0dGluZygnd2F6dWgubW9uaXRvcmluZy5mcmVxdWVuY3knLCBhcHBDb25maWcsIGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3JpbmcuZnJlcXVlbmN5JykpO1xuICAgIE1PTklUT1JJTkdfQ1JPTl9GUkVRID0gcGFyc2VDcm9uKE1PTklUT1JJTkdfRlJFUVVFTkNZKTtcbiAgICBNT05JVE9SSU5HX0NSRUFUSU9OID0gZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3JpbmcuY3JlYXRpb24nLCBhcHBDb25maWcsIGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3JpbmcuY3JlYXRpb24nKSk7XG5cbiAgICBNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4gPSBnZXRBcHBDb25maWd1cmF0aW9uU2V0dGluZygnd2F6dWgubW9uaXRvcmluZy5wYXR0ZXJuJywgYXBwQ29uZmlnLCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLnBhdHRlcm4nKSk7XG4gICAgY29uc3QgbGFzdENoYXJJbmRleFBhdHRlcm4gPSBNT05JVE9SSU5HX0lOREVYX1BBVFRFUk5bTU9OSVRPUklOR19JTkRFWF9QQVRURVJOLmxlbmd0aCAtIDFdO1xuICAgIGlmIChsYXN0Q2hhckluZGV4UGF0dGVybiAhPT0gJyonKSB7XG4gICAgICBNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4gKz0gJyonO1xuICAgIH07XG4gICAgTU9OSVRPUklOR19JTkRFWF9QUkVGSVggPSBNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4uc2xpY2UoMCwgTU9OSVRPUklOR19JTkRFWF9QQVRURVJOLmxlbmd0aCAtIDEpO1xuXG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6aW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uJyxcbiAgICAgIGB3YXp1aC5tb25pdG9yaW5nLmVuYWJsZWQ6ICR7TU9OSVRPUklOR19FTkFCTEVEfWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbicsXG4gICAgICBgd2F6dWgubW9uaXRvcmluZy5mcmVxdWVuY3k6ICR7TU9OSVRPUklOR19GUkVRVUVOQ1l9ICgke01PTklUT1JJTkdfQ1JPTl9GUkVRfSlgLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzppbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24nLFxuICAgICAgYHdhenVoLm1vbml0b3JpbmcucGF0dGVybjogJHtNT05JVE9SSU5HX0lOREVYX1BBVFRFUk59IChpbmRleCBwcmVmaXg6ICR7TU9OSVRPUklOR19JTkRFWF9QUkVGSVh9KWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBjb25zdCBlcnJvck1lc3NhZ2UgPSBlcnJvci5tZXNzYWdlIHx8IGVycm9yO1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbicsXG4gICAgICBlcnJvck1lc3NhZ2VcbiAgICApO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yTWVzc2FnZSlcbiAgfVxufTtcblxuLyoqXG4gKiBNYWluLiBGaXJzdCBleGVjdXRpb24gd2hlbiBpbnN0YWxsaW5nIC8gbG9hZGluZyBBcHAuXG4gKiBAcGFyYW0gY29udGV4dFxuICovXG5hc3luYyBmdW5jdGlvbiBpbml0KGNvbnRleHQpIHtcbiAgdHJ5IHtcbiAgICBpZiAoTU9OSVRPUklOR19FTkFCTEVEKSB7XG4gICAgICBhd2FpdCBjaGVja1RlbXBsYXRlKGNvbnRleHQpO1xuICAgIH07XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc3QgZXJyb3JNZXNzYWdlID0gZXJyb3IubWVzc2FnZSB8fCBlcnJvcjtcbiAgICBsb2coJ21vbml0b3Jpbmc6aW5pdCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yTWVzc2FnZSk7XG4gIH1cbn1cblxuLyoqXG4gKiBWZXJpZnkgd2F6dWgtYWdlbnQgdGVtcGxhdGVcbiAqL1xuYXN5bmMgZnVuY3Rpb24gY2hlY2tUZW1wbGF0ZShjb250ZXh0KSB7XG4gIHRyeSB7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y2hlY2tUZW1wbGF0ZScsXG4gICAgICAnVXBkYXRpbmcgdGhlIG1vbml0b3JpbmcgdGVtcGxhdGUnLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gQ2hlY2sgaWYgdGhlIHRlbXBsYXRlIGFscmVhZHkgZXhpc3RzXG4gICAgICBjb25zdCBjdXJyZW50VGVtcGxhdGUgPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5nZXRUZW1wbGF0ZSh7XG4gICAgICAgIG5hbWU6IFdBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRVxuICAgICAgfSk7XG4gICAgICAvLyBDb3B5IGFscmVhZHkgY3JlYXRlZCBpbmRleCBwYXR0ZXJuc1xuICAgICAgbW9uaXRvcmluZ1RlbXBsYXRlLmluZGV4X3BhdHRlcm5zID0gY3VycmVudFRlbXBsYXRlLmJvZHlbV0FaVUhfTU9OSVRPUklOR19URU1QTEFURV9OQU1FXS5pbmRleF9wYXR0ZXJucztcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgLy8gSW5pdCB3aXRoIHRoZSBkZWZhdWx0IGluZGV4IHBhdHRlcm5cbiAgICAgIG1vbml0b3JpbmdUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucyA9IFtnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLnBhdHRlcm4nKV07XG4gICAgfVxuXG4gICAgLy8gQ2hlY2sgaWYgdGhlIHVzZXIgaXMgdXNpbmcgYSBjdXN0b20gcGF0dGVybiBhbmQgYWRkIGl0IHRvIHRoZSB0ZW1wbGF0ZSBpZiBpdCBkb2VzXG4gICAgaWYgKCFtb25pdG9yaW5nVGVtcGxhdGUuaW5kZXhfcGF0dGVybnMuaW5jbHVkZXMoTU9OSVRPUklOR19JTkRFWF9QQVRURVJOKSkge1xuICAgICAgbW9uaXRvcmluZ1RlbXBsYXRlLmluZGV4X3BhdHRlcm5zLnB1c2goTU9OSVRPUklOR19JTkRFWF9QQVRURVJOKTtcbiAgICB9O1xuXG4gICAgLy8gVXBkYXRlIHRoZSBtb25pdG9yaW5nIHRlbXBsYXRlXG4gICAgYXdhaXQgY29udGV4dC5jb3JlLm9wZW5zZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMucHV0VGVtcGxhdGUoe1xuICAgICAgbmFtZTogV0FaVUhfTU9OSVRPUklOR19URU1QTEFURV9OQU1FLFxuICAgICAgYm9keTogbW9uaXRvcmluZ1RlbXBsYXRlXG4gICAgfSk7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y2hlY2tUZW1wbGF0ZScsXG4gICAgICAnVXBkYXRlZCB0aGUgbW9uaXRvcmluZyB0ZW1wbGF0ZScsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBjb25zdCBlcnJvck1lc3NhZ2UgPSBgU29tZXRoaW5nIHdlbnQgd3JvbmcgdXBkYXRpbmcgdGhlIG1vbml0b3JpbmcgdGVtcGxhdGUgJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWA7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y2hlY2tUZW1wbGF0ZScsXG4gICAgICBlcnJvck1lc3NhZ2VcbiAgICApO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKG1vbml0b3JpbmdFcnJvckxvZ0NvbG9ycywgZXJyb3JNZXNzYWdlKTtcbiAgICB0aHJvdyBlcnJvcjtcbiAgfVxufVxuXG4vKipcbiAqIFNhdmUgYWdlbnQgc3RhdHVzIGludG8gZWxhc3RpY3NlYXJjaCwgY3JlYXRlIGluZGV4IGFuZC9vciBpbnNlcnQgZG9jdW1lbnRcbiAqIEBwYXJhbSB7Kn0gY29udGV4dFxuICogQHBhcmFtIHsqfSBkYXRhXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGluc2VydE1vbml0b3JpbmdEYXRhRWxhc3RpY3NlYXJjaChjb250ZXh0LCBkYXRhKSB7XG4gIGNvbnN0IG1vbml0b3JpbmdJbmRleE5hbWUgPSBNT05JVE9SSU5HX0lOREVYX1BSRUZJWCArIGluZGV4RGF0ZShNT05JVE9SSU5HX0NSRUFUSU9OKTtcbiAgaWYgKCFNT05JVE9SSU5HX0VOQUJMRUQpIHtcbiAgICByZXR1cm47XG4gIH07XG4gIHRyeSB7XG4gICAgYXdhaXQgdHJ5Q2F0Y2hGb3JJbmRleFBlcm1pc3Npb25FcnJvcihtb25pdG9yaW5nSW5kZXhOYW1lKShhc3luYyAoKSA9PiB7XG4gICAgICBjb25zdCBleGlzdHMgPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoeyBpbmRleDogbW9uaXRvcmluZ0luZGV4TmFtZSB9KTtcbiAgICAgIGlmICghZXhpc3RzLmJvZHkpIHtcbiAgICAgICAgYXdhaXQgY3JlYXRlSW5kZXgoY29udGV4dCwgbW9uaXRvcmluZ0luZGV4TmFtZSk7XG4gICAgICB9O1xuXG4gICAgICAvLyBVcGRhdGUgdGhlIGluZGV4IGNvbmZpZ3VyYXRpb25cbiAgICAgIGNvbnN0IGFwcENvbmZpZyA9IGdldENvbmZpZ3VyYXRpb24oKTtcbiAgICAgIGNvbnN0IGluZGV4Q29uZmlndXJhdGlvbiA9IGJ1aWxkSW5kZXhTZXR0aW5ncyhcbiAgICAgICAgYXBwQ29uZmlnLFxuICAgICAgICAnd2F6dWgubW9uaXRvcmluZycsXG4gICAgICAgIGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3Jpbmcuc2hhcmRzJylcbiAgICAgICk7XG5cbiAgICAgIC8vIFRvIHVwZGF0ZSB0aGUgaW5kZXggc2V0dGluZ3Mgd2l0aCB0aGlzIGNsaWVudCBpcyByZXF1aXJlZCBjbG9zZSB0aGUgaW5kZXgsIHVwZGF0ZSB0aGUgc2V0dGluZ3MgYW5kIG9wZW4gaXRcbiAgICAgIC8vIE51bWJlciBvZiBzaGFyZHMgaXMgbm90IGR5bmFtaWMgc28gZGVsZXRlIHRoYXQgc2V0dGluZyBpZiBpdCdzIGdpdmVuXG4gICAgICBkZWxldGUgaW5kZXhDb25maWd1cmF0aW9uLnNldHRpbmdzLmluZGV4Lm51bWJlcl9vZl9zaGFyZHM7XG4gICAgICBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5wdXRTZXR0aW5ncyh7XG4gICAgICAgIGluZGV4OiBtb25pdG9yaW5nSW5kZXhOYW1lLFxuICAgICAgICBib2R5OiBpbmRleENvbmZpZ3VyYXRpb25cbiAgICAgIH0pO1xuXG4gICAgICAvLyBJbnNlcnQgZGF0YSB0byB0aGUgbW9uaXRvcmluZyBpbmRleFxuICAgICAgYXdhaXQgaW5zZXJ0RGF0YVRvSW5kZXgoY29udGV4dCwgbW9uaXRvcmluZ0luZGV4TmFtZSwgZGF0YSk7XG4gICAgfSkoKTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBsb2coJ21vbml0b3Jpbmc6aW5zZXJ0TW9uaXRvcmluZ0RhdGFFbGFzdGljc2VhcmNoJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoZXJyb3IubWVzc2FnZSk7XG4gIH1cbn1cblxuLyoqXG4gKiBJbnNlcnRpbmcgb25lIGRvY3VtZW50IHBlciBhZ2VudCBpbnRvIEVsYXN0aWMuIEJ1bGsuXG4gKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnRcbiAqIEBwYXJhbSB7U3RyaW5nfSBpbmRleE5hbWUgVGhlIG5hbWUgZm9yIHRoZSBpbmRleCAoZS5nLiBkYWlseTogd2F6dWgtbW9uaXRvcmluZy1ZWVlZLk1NLkREKVxuICogQHBhcmFtIHsqfSBkYXRhXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGluc2VydERhdGFUb0luZGV4KGNvbnRleHQsIGluZGV4TmFtZTogc3RyaW5nLCBkYXRhOiB7IGFnZW50czogYW55W10sIGFwaUhvc3QgfSkge1xuICBjb25zdCB7IGFnZW50cywgYXBpSG9zdCB9ID0gZGF0YTtcbiAgdHJ5IHtcbiAgICBpZiAoYWdlbnRzLmxlbmd0aCA+IDApIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ21vbml0b3Jpbmc6aW5zZXJ0RGF0YVRvSW5kZXgnLFxuICAgICAgICBgQnVsayBkYXRhIHRvIGluZGV4ICR7aW5kZXhOYW1lfSBmb3IgJHthZ2VudHMubGVuZ3RofSBhZ2VudHNgLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuXG4gICAgICBjb25zdCBib2R5QnVsayA9IGFnZW50cy5tYXAoYWdlbnQgPT4ge1xuICAgICAgICBjb25zdCBhZ2VudEluZm8gPSB7IC4uLmFnZW50IH07XG4gICAgICAgIGFnZW50SW5mb1sndGltZXN0YW1wJ10gPSBuZXcgRGF0ZShEYXRlLm5vdygpKS50b0lTT1N0cmluZygpO1xuICAgICAgICBhZ2VudEluZm8uaG9zdCA9IGFnZW50Lm1hbmFnZXI7XG4gICAgICAgIGFnZW50SW5mby5jbHVzdGVyID0geyBuYW1lOiBhcGlIb3N0LmNsdXN0ZXJOYW1lID8gYXBpSG9zdC5jbHVzdGVyTmFtZSA6ICdkaXNhYmxlZCcgfTtcbiAgICAgICAgcmV0dXJuIGB7IFwiaW5kZXhcIjogIHsgXCJfaW5kZXhcIjogXCIke2luZGV4TmFtZX1cIiB9IH1cXG4ke0pTT04uc3RyaW5naWZ5KGFnZW50SW5mbyl9XFxuYDtcbiAgICAgIH0pLmpvaW4oJycpO1xuXG4gICAgICBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuYnVsayh7XG4gICAgICAgIGluZGV4OiBpbmRleE5hbWUsXG4gICAgICAgIGJvZHk6IGJvZHlCdWxrXG4gICAgICB9KTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ21vbml0b3Jpbmc6aW5zZXJ0RGF0YVRvSW5kZXgnLFxuICAgICAgICBgQnVsayBkYXRhIHRvIGluZGV4ICR7aW5kZXhOYW1lfSBmb3IgJHthZ2VudHMubGVuZ3RofSBhZ2VudHMgY29tcGxldGVkYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICB9XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6aW5zZXJ0RGF0YVRvSW5kZXgnLFxuICAgICAgYEVycm9yIGluc2VydGluZyBhZ2VudCBkYXRhIGludG8gZWxhc3RpY3NlYXJjaC4gQnVsayByZXF1ZXN0IGZhaWxlZCBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8XG4gICAgICBlcnJvcn1gXG4gICAgKTtcbiAgfVxufVxuXG4vKipcbiAqIENyZWF0ZSB0aGUgd2F6dWgtbW9uaXRvcmluZyBpbmRleFxuICogQHBhcmFtIHsqfSBjb250ZXh0IGNvbnRleHRcbiAqIEBwYXJhbSB7U3RyaW5nfSBpbmRleE5hbWUgVGhlIG5hbWUgZm9yIHRoZSBpbmRleCAoZS5nLiBkYWlseTogd2F6dWgtbW9uaXRvcmluZy1ZWVlZLk1NLkREKVxuICovXG5hc3luYyBmdW5jdGlvbiBjcmVhdGVJbmRleChjb250ZXh0LCBpbmRleE5hbWU6IHN0cmluZykge1xuICB0cnkge1xuICAgIGlmICghTU9OSVRPUklOR19FTkFCTEVEKSByZXR1cm47XG4gICAgY29uc3QgYXBwQ29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuXG4gICAgY29uc3QgSW5kZXhDb25maWd1cmF0aW9uID0ge1xuICAgICAgc2V0dGluZ3M6IHtcbiAgICAgICAgaW5kZXg6IHtcbiAgICAgICAgICBudW1iZXJfb2Zfc2hhcmRzOiBnZXRBcHBDb25maWd1cmF0aW9uU2V0dGluZygnd2F6dWgubW9uaXRvcmluZy5zaGFyZHMnLCBhcHBDb25maWcsIGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3Jpbmcuc2hhcmRzJykpLFxuICAgICAgICAgIG51bWJlcl9vZl9yZXBsaWNhczogZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3JpbmcucmVwbGljYXMnLCBhcHBDb25maWcsIGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3JpbmcucmVwbGljYXMnKSlcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH07XG5cbiAgICBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5jcmVhdGUoe1xuICAgICAgaW5kZXg6IGluZGV4TmFtZSxcbiAgICAgIGJvZHk6IEluZGV4Q29uZmlndXJhdGlvblxuICAgIH0pO1xuXG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y3JlYXRlSW5kZXgnLFxuICAgICAgYFN1Y2Nlc3NmdWxseSBjcmVhdGVkIG5ldyBpbmRleDogJHtpbmRleE5hbWV9YCxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IGBDb3VsZCBub3QgY3JlYXRlICR7aW5kZXhOYW1lfSBpbmRleCBvbiBlbGFzdGljc2VhcmNoIGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YDtcbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzpjcmVhdGVJbmRleCcsXG4gICAgICBlcnJvck1lc3NhZ2VcbiAgICApO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yTWVzc2FnZSk7XG4gIH1cbn1cblxuLyoqXG4qIFdhaXQgdW50aWwgS2liYW5hIHNlcnZlciBpcyByZWFkeVxuKi9cbmFzeW5jIGZ1bmN0aW9uIGNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMoY29udGV4dCkge1xuICB0cnkge1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMnLFxuICAgICAgJ1dhaXRpbmcgZm9yIEtpYmFuYSBhbmQgRWxhc3RpY3NlYXJjaCBzZXJ2ZXJzIHRvIGJlIHJlYWR5Li4uJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuXG4gICAgYXdhaXQgY2hlY2tFbGFzdGljc2VhcmNoU2VydmVyKGNvbnRleHQpO1xuICAgIGF3YWl0IGluaXQoY29udGV4dCk7XG4gICAgcmV0dXJuO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMnLFxuICAgICAgZXJyb3IubWVzYWdlIHx8IGVycm9yXG4gICAgKTtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgZGVsYXlBc1Byb21pc2UoMzAwMCk7XG4gICAgICBhd2FpdCBjaGVja1BsdWdpblBsYXRmb3JtU3RhdHVzKGNvbnRleHQpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7IH07XG4gIH1cbn1cblxuXG4vKipcbiAqIENoZWNrIEVsYXN0aWNzZWFyY2ggU2VydmVyIHN0YXR1cyBhbmQgS2liYW5hIGluZGV4IHByZXNlbmNlXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGNoZWNrRWxhc3RpY3NlYXJjaFNlcnZlcihjb250ZXh0KSB7XG4gIHRyeSB7XG4gICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICBpbmRleDogY29udGV4dC5zZXJ2ZXIuY29uZmlnLm9wZW5zZWFyY2hEYXNoYm9hcmRzLmluZGV4XG4gICAgfSk7XG5cbiAgICByZXR1cm4gZGF0YS5ib2R5O1xuICAgIC8vIFRPRE86IGNoZWNrIGlmIEVsYXN0aWNzZWFyY2ggY2FuIHJlY2VpdmUgcmVxdWVzdHNcbiAgICAvLyBpZiAoZGF0YSkge1xuICAgIC8vICAgY29uc3QgcGx1Z2luc0RhdGEgPSBhd2FpdCB0aGlzLnNlcnZlci5wbHVnaW5zLmVsYXN0aWNzZWFyY2gud2FpdFVudGlsUmVhZHkoKTtcbiAgICAvLyAgIHJldHVybiBwbHVnaW5zRGF0YTtcbiAgICAvLyB9XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGRhdGEpO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZygnbW9uaXRvcmluZzpjaGVja0VsYXN0aWNzZWFyY2hTZXJ2ZXInLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICB9XG59XG5cbmNvbnN0IGZha2VSZXNwb25zZUVuZHBvaW50ID0ge1xuICBvazogKGJvZHk6IGFueSkgPT4gYm9keSxcbiAgY3VzdG9tOiAoYm9keTogYW55KSA9PiBib2R5LFxufVxuLyoqXG4gKiBHZXQgQVBJIGNvbmZpZ3VyYXRpb24gZnJvbSBlbGFzdGljIGFuZCBjYWxsYmFjayB0byBsb2FkQ3JlZGVudGlhbHNcbiAqL1xuYXN5bmMgZnVuY3Rpb24gZ2V0SG9zdHNDb25maWd1cmF0aW9uKCkge1xuICB0cnkge1xuICAgIGNvbnN0IGhvc3RzID0gYXdhaXQgd2F6dWhIb3N0Q29udHJvbGxlci5nZXRIb3N0c0VudHJpZXMoZmFsc2UsIGZhbHNlLCBmYWtlUmVzcG9uc2VFbmRwb2ludCk7XG4gICAgaWYgKGhvc3RzLmJvZHkubGVuZ3RoKSB7XG4gICAgICByZXR1cm4gaG9zdHMuYm9keTtcbiAgICB9O1xuXG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Z2V0Q29uZmlnJyxcbiAgICAgICdUaGVyZSBhcmUgbm8gV2F6dWggQVBJIGVudHJpZXMgeWV0JyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICAgIHJldHVybiBQcm9taXNlLnJlamVjdCh7XG4gICAgICBlcnJvcjogJ25vIGNyZWRlbnRpYWxzJyxcbiAgICAgIGVycm9yX2NvZGU6IDFcbiAgICB9KTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBsb2coJ21vbml0b3Jpbmc6Z2V0SG9zdHNDb25maWd1cmF0aW9uJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHtcbiAgICAgIGVycm9yOiAnbm8gd2F6dWggaG9zdHMnLFxuICAgICAgZXJyb3JfY29kZTogMlxuICAgIH0pO1xuICB9XG59XG5cbi8qKlxuICAgKiBUYXNrIHVzZWQgYnkgdGhlIGNyb24gam9iLlxuICAgKi9cbmFzeW5jIGZ1bmN0aW9uIGNyb25UYXNrKGNvbnRleHQpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCB0ZW1wbGF0ZU1vbml0b3JpbmcgPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5nZXRUZW1wbGF0ZSh7IG5hbWU6IFdBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRSB9KTtcblxuICAgIGNvbnN0IGFwaUhvc3RzID0gYXdhaXQgZ2V0SG9zdHNDb25maWd1cmF0aW9uKCk7XG4gICAgY29uc3QgYXBpSG9zdHNVbmlxdWUgPSAoYXBpSG9zdHMgfHwgW10pLmZpbHRlcihcbiAgICAgIChhcGlIb3N0LCBpbmRleCwgc2VsZikgPT5cbiAgICAgICAgaW5kZXggPT09XG4gICAgICAgIHNlbGYuZmluZEluZGV4KFxuICAgICAgICAgIHQgPT5cbiAgICAgICAgICAgIHQudXNlciA9PT0gYXBpSG9zdC51c2VyICYmXG4gICAgICAgICAgICB0LnBhc3N3b3JkID09PSBhcGlIb3N0LnBhc3N3b3JkICYmXG4gICAgICAgICAgICB0LnVybCA9PT0gYXBpSG9zdC51cmwgJiZcbiAgICAgICAgICAgIHQucG9ydCA9PT0gYXBpSG9zdC5wb3J0XG4gICAgICAgIClcbiAgICApO1xuICAgIGZvciAobGV0IGFwaUhvc3Qgb2YgYXBpSG9zdHNVbmlxdWUpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgYWdlbnRzLCBhcGlIb3N0OiBob3N0IH0gPSBhd2FpdCBnZXRBcGlJbmZvKGNvbnRleHQsIGFwaUhvc3QpO1xuICAgICAgICBhd2FpdCBpbnNlcnRNb25pdG9yaW5nRGF0YUVsYXN0aWNzZWFyY2goY29udGV4dCwgeyBhZ2VudHMsIGFwaUhvc3Q6IGhvc3QgfSk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuXG4gICAgICB9O1xuICAgIH1cbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAvLyBSZXRyeSB0byBjYWxsIGl0c2VsZiBhZ2FpbiBpZiBLaWJhbmEgaW5kZXggaXMgbm90IHJlYWR5IHlldFxuICAgIC8vIHRyeSB7XG4gICAgLy8gICBpZiAoXG4gICAgLy8gICAgIHRoaXMud3pXcmFwcGVyLmJ1aWxkaW5nS2liYW5hSW5kZXggfHxcbiAgICAvLyAgICAgKChlcnJvciB8fCB7fSkuc3RhdHVzID09PSA0MDQgJiZcbiAgICAvLyAgICAgICAoZXJyb3IgfHwge30pLmRpc3BsYXlOYW1lID09PSAnTm90Rm91bmQnKVxuICAgIC8vICAgKSB7XG4gICAgLy8gICAgIGF3YWl0IGRlbGF5QXNQcm9taXNlKDEwMDApO1xuICAgIC8vICAgICByZXR1cm4gY3JvblRhc2soY29udGV4dCk7XG4gICAgLy8gICB9XG4gICAgLy8gfSBjYXRjaCAoZXJyb3IpIHt9IC8vZXNsaW50LWRpc2FibGUtbGluZVxuXG4gICAgbG9nKCdtb25pdG9yaW5nOmNyb25UYXNrJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gIH1cbn1cblxuLyoqXG4gKiBHZXQgQVBJIGFuZCBhZ2VudHMgaW5mb1xuICogQHBhcmFtIGNvbnRleHRcbiAqIEBwYXJhbSBhcGlIb3N0XG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGdldEFwaUluZm8oY29udGV4dCwgYXBpSG9zdCkge1xuICB0cnkge1xuICAgIGxvZygnbW9uaXRvcmluZzpnZXRBcGlJbmZvJywgYEdldHRpbmcgQVBJIGluZm8gZm9yICR7YXBpSG9zdC5pZH1gLCAnZGVidWcnKTtcbiAgICBjb25zdCByZXNwb25zZUlzQ2x1c3RlciA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KCdHRVQnLCAnL2NsdXN0ZXIvc3RhdHVzJywge30sIHsgYXBpSG9zdElEOiBhcGlIb3N0LmlkIH0pO1xuICAgIGNvbnN0IGlzQ2x1c3RlciA9ICgoKHJlc3BvbnNlSXNDbHVzdGVyIHx8IHt9KS5kYXRhIHx8IHt9KS5kYXRhIHx8IHt9KS5lbmFibGVkID09PSAneWVzJztcbiAgICBpZiAoaXNDbHVzdGVyKSB7XG4gICAgICBjb25zdCByZXNwb25zZUNsdXN0ZXJJbmZvID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoJ0dFVCcsIGAvY2x1c3Rlci9sb2NhbC9pbmZvYCwge30sIHsgYXBpSG9zdElEOiBhcGlIb3N0LmlkIH0pO1xuICAgICAgYXBpSG9zdC5jbHVzdGVyTmFtZSA9IHJlc3BvbnNlQ2x1c3RlckluZm8uZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLmNsdXN0ZXI7XG4gICAgfTtcbiAgICBjb25zdCBhZ2VudHMgPSBhd2FpdCBmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0KGNvbnRleHQsIGFwaUhvc3QpO1xuICAgIHJldHVybiB7IGFnZW50cywgYXBpSG9zdCB9O1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZygnbW9uaXRvcmluZzpnZXRBcGlJbmZvJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn07XG5cbi8qKlxuICogRmV0Y2ggYWxsIGFnZW50cyBmb3IgdGhlIEFQSSBwcm92aWRlZFxuICogQHBhcmFtIGNvbnRleHRcbiAqIEBwYXJhbSBhcGlIb3N0XG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QoY29udGV4dCwgYXBpSG9zdCkge1xuICBsZXQgYWdlbnRzID0gW107XG4gIHRyeSB7XG4gICAgbG9nKCdtb25pdG9yaW5nOmZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QnLCBgR2V0dGluZyBhbGwgYWdlbnRzIGZyb20gQXBpSUQ6ICR7YXBpSG9zdC5pZH1gLCAnZGVidWcnKTtcbiAgICBjb25zdCByZXNwb25zZUFnZW50c0NvdW50ID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzSW50ZXJuYWxVc2VyLnJlcXVlc3QoXG4gICAgICAnR0VUJyxcbiAgICAgICcvYWdlbnRzJyxcbiAgICAgIHtcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgb2Zmc2V0OiAwLFxuICAgICAgICAgIGxpbWl0OiAxLFxuICAgICAgICAgIHE6ICdpZCE9MDAwJ1xuICAgICAgICB9XG4gICAgICB9LCB7IGFwaUhvc3RJRDogYXBpSG9zdC5pZCB9KTtcblxuICAgIGNvbnN0IGFnZW50c0NvdW50ID0gcmVzcG9uc2VBZ2VudHNDb3VudC5kYXRhLmRhdGEudG90YWxfYWZmZWN0ZWRfaXRlbXM7XG4gICAgbG9nKCdtb25pdG9yaW5nOmZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QnLCBgQXBpSUQ6ICR7YXBpSG9zdC5pZH0sIEFnZW50IGNvdW50OiAke2FnZW50c0NvdW50fWAsICdkZWJ1ZycpO1xuXG4gICAgbGV0IHBheWxvYWQgPSB7XG4gICAgICBvZmZzZXQ6IDAsXG4gICAgICBsaW1pdDogNTAwLFxuICAgICAgcTogJ2lkIT0wMDAnXG4gICAgfTtcblxuICAgIHdoaWxlIChhZ2VudHMubGVuZ3RoIDwgYWdlbnRzQ291bnQgJiYgcGF5bG9hZC5vZmZzZXQgPCBhZ2VudHNDb3VudCkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgLypcbiAgICAgICAgVE9ETzogSW1wcm92ZSB0aGUgcGVyZm9ybWFuY2Ugb2YgcmVxdWVzdCB3aXRoOlxuICAgICAgICAgIC0gUmVkdWNlIHRoZSBudW1iZXIgb2YgcmVxdWVzdHMgdG8gdGhlIFdhenVoIEFQSVxuICAgICAgICAgIC0gUmVkdWNlIChpZiBwb3NzaWJsZSkgdGhlIHF1YW50aXR5IG9mIGRhdGEgdG8gaW5kZXggYnkgZG9jdW1lbnRcblxuICAgICAgICBSZXF1aXJlbWVudHM6XG4gICAgICAgICAgLSBSZXNlYXJjaCBhYm91dCB0aGUgbmVjY2VzYXJ5IGRhdGEgdG8gaW5kZXguXG5cbiAgICAgICAgSG93IHRvIGRvOlxuICAgICAgICAgIC0gV2F6dWggQVBJIHJlcXVlc3Q6XG4gICAgICAgICAgICAtIHNlbGVjdCB0aGUgcmVxdWlyZWQgZGF0YSB0byByZXRyaWV2ZSBkZXBlbmRpbmcgb24gaXMgcmVxdWlyZWQgdG8gaW5kZXggKHVzaW5nIHRoZSBgc2VsZWN0YCBxdWVyeSBwYXJhbSlcbiAgICAgICAgICAgIC0gaW5jcmVhc2UgdGhlIGxpbWl0IG9mIHJlc3VsdHMgdG8gcmV0cmlldmUgKGN1cnJlbnRseSwgdGhlIHJlcXVlc3RzIHVzZSB0aGUgcmVjb21tZW5kZWQgdmFsdWU6IDUwMCkuXG4gICAgICAgICAgICAgIFNlZSB0aGUgYWxsb3dlZCB2YWx1ZXMuIFRoaXMgZGVwZW5kcyBvbiB0aGUgc2VsZWN0ZWQgZGF0YSBiZWNhdXNlIHRoZSByZXNwb25zZSBjb3VsZCBmYWlsIGlmIGNvbnRhaW5zIGEgbG90IG9mIGRhdGFcbiAgICAgICAgKi9cbiAgICAgICAgY29uc3QgcmVzcG9uc2VBZ2VudHMgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdChcbiAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICBgL2FnZW50c2AsXG4gICAgICAgICAgeyBwYXJhbXM6IHBheWxvYWQgfSxcbiAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSG9zdC5pZCB9XG4gICAgICAgICk7XG4gICAgICAgIGFnZW50cyA9IFsuLi5hZ2VudHMsIC4uLnJlc3BvbnNlQWdlbnRzLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc107XG4gICAgICAgIHBheWxvYWQub2Zmc2V0ICs9IHBheWxvYWQubGltaXQ7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coJ21vbml0b3Jpbmc6ZmV0Y2hBbGxBZ2VudHNGcm9tQXBpSG9zdCcsIGBBcGlJRDogJHthcGlIb3N0LmlkfSwgRXJyb3IgcmVxdWVzdCB3aXRoIG9mZnNldC9saW1pdCAke3BheWxvYWQub2Zmc2V0fS8ke3BheWxvYWQubGltaXR9OiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YCk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBhZ2VudHM7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKCdtb25pdG9yaW5nOmZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QnLCBgQXBpSUQ6ICR7YXBpSG9zdC5pZH0uIEVycm9yOiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YCk7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn07XG5cbi8qKlxuICogU3RhcnQgdGhlIGNyb24gam9iXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBqb2JNb25pdG9yaW5nUnVuKGNvbnRleHQpIHtcbiAgLy8gSW5pdCB0aGUgbW9uaXRvcmluZyB2YXJpYWJsZXNcbiAgaW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uKGNvbnRleHQpO1xuICAvLyBDaGVjayBLaWJhbmEgaW5kZXggYW5kIGlmIGl0IGlzIHByZXBhcmVkLCBzdGFydCB0aGUgaW5pdGlhbGl6YXRpb24gb2YgV2F6dWggQXBwLlxuICBhd2FpdCBjaGVja1BsdWdpblBsYXRmb3JtU3RhdHVzKGNvbnRleHQpO1xuICAvLyAvLyBSdW4gdGhlIGNyb24gam9iIG9ubHkgaXQgaXQncyBlbmFibGVkXG4gIGlmIChNT05JVE9SSU5HX0VOQUJMRUQpIHtcbiAgICBjcm9uVGFzayhjb250ZXh0KTtcbiAgICBjcm9uLnNjaGVkdWxlKE1PTklUT1JJTkdfQ1JPTl9GUkVRLCAoKSA9PiBjcm9uVGFzayhjb250ZXh0KSk7XG4gIH1cbn1cblxuIl19