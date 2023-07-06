"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jobInitializeRun = jobInitializeRun;

var _logger = require("../../lib/logger");

var _package = _interopRequireDefault(require("../../../package.json"));

var _kibanaTemplate = require("../../integration-files/kibana-template");

var _getConfiguration = require("../../lib/get-configuration");

var _os = require("os");

var _fs = _interopRequireDefault(require("fs"));

var _constants = require("../../../common/constants");

var _filesystem = require("../../lib/filesystem");

var _lodash = _interopRequireDefault(require("lodash"));

var _settings = require("../../../common/services/settings");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
 * Wazuh app - Module for app initialization
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
function jobInitializeRun(context) {
  const PLUGIN_PLATFORM_INDEX = context.server.config.opensearchDashboards.index;
  (0, _logger.log)('initialize', `${_constants.PLUGIN_PLATFORM_NAME} index: ${PLUGIN_PLATFORM_INDEX}`, 'info');
  (0, _logger.log)('initialize', `App revision: ${_package.default.revision}`, 'info');
  let configurationFile = {};
  let pattern = null; // Read config from package.json and wazuh.yml

  try {
    configurationFile = (0, _getConfiguration.getConfiguration)();
    pattern = configurationFile && typeof configurationFile.pattern !== 'undefined' ? configurationFile.pattern : (0, _settings.getSettingDefaultValue)('pattern');
  } catch (error) {
    (0, _logger.log)('initialize', error.message || error);
    context.wazuh.logger.error('Something went wrong while reading the configuration.' + (error.message || error));
  }

  try {
    // RAM in MB
    const ram = Math.ceil((0, _os.totalmem)() / 1024 / 1024);
    (0, _logger.log)('initialize', `Total RAM: ${ram}MB`, 'info');
  } catch (error) {
    (0, _logger.log)('initialize', `Could not check total RAM due to: ${error.message || error}`);
  } // Save Wazuh App setup


  const saveConfiguration = async (hosts = {}) => {
    try {
      const commonDate = new Date().toISOString();
      const configuration = {
        name: _constants.PLUGIN_APP_NAME,
        'app-version': _package.default.version,
        revision: _package.default.revision,
        installationDate: commonDate,
        lastRestart: commonDate,
        hosts
      };

      try {
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDataDirectoryIfNotExists)('config');
        (0, _logger.log)('initialize:saveConfiguration', `Saving configuration in registry file: ${JSON.stringify(configuration)}`, 'debug');
        await _fs.default.writeFileSync(_constants.WAZUH_DATA_CONFIG_REGISTRY_PATH, JSON.stringify(configuration), 'utf8');
        (0, _logger.log)('initialize:saveConfiguration', 'Wazuh configuration registry saved.', 'debug');
      } catch (error) {
        (0, _logger.log)('initialize:saveConfiguration', error.message || error);
        context.wazuh.logger.error('Could not create Wazuh configuration registry');
      }
    } catch (error) {
      (0, _logger.log)('initialize:saveConfiguration', error.message || error);
      context.wazuh.logger.error('Error creating wazuh-registry.json file.');
    }
  };
  /**
   * Checks if the .wazuh-registry.json file exists:
   * - yes: check the plugin version and revision match the values stored in the registry file.
   *  If not, then it migrates the data rebuilding the registry file.
   * - no: create the file with empty hosts
   */


  const checkWazuhRegistry = async () => {
    (0, _logger.log)('initialize:checkwazuhRegistry', 'Checking wazuh-registry.json file.', 'debug');

    if (!_fs.default.existsSync(_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH)) {
      throw new Error(`The data directory is missing in the ${_constants.PLUGIN_PLATFORM_NAME} root instalation. Create the directory in ${_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH} and give it the required permissions (sudo mkdir ${_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH};sudo chown -R ${_constants.PLUGIN_PLATFORM_INSTALLATION_USER}:${_constants.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP} ${_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH}). After restart the ${_constants.PLUGIN_PLATFORM_NAME} service.`);
    }

    ;

    if (!_fs.default.existsSync(_constants.WAZUH_DATA_CONFIG_REGISTRY_PATH)) {
      (0, _logger.log)('initialize:checkwazuhRegistry', 'wazuh-registry.json file does not exist. Initializing configuration.', 'debug'); // Create the app registry file for the very first time

      await saveConfiguration();
    } else {
      // If this function fails, it throws an exception
      const source = JSON.parse(_fs.default.readFileSync(_constants.WAZUH_DATA_CONFIG_REGISTRY_PATH, 'utf8')); // Check if the stored revision differs from the package.json revision

      const isUpgradedApp = _package.default.revision !== source.revision || _package.default.version !== source['app-version']; // Rebuild the registry file if revision or version fields are differents

      if (isUpgradedApp) {
        (0, _logger.log)('initialize:checkwazuhRegistry', 'Wazuh app revision or version changed, regenerating wazuh-registry.json.', 'info'); // Rebuild the registry file `wazuh-registry.json`
        // Get the supported extensions for the installed plugin

        const supportedDefaultExtensionsConfiguration = Object.entries((0, _settings.getSettingsDefault)()).filter(([setting]) => setting.startsWith('extensions.')).map(([setting, settingValue]) => {
          return [setting.split('.')[1], settingValue];
        }); // Get the supported extensions by ID

        const supportedDefaultExtensionsNames = supportedDefaultExtensionsConfiguration.map(([setting]) => setting); // Generate the hosts data, migrating the extensions.
        // Keep the supported and existent extensions for the installed plugin with the configurated value
        // Add the extensions with default values that didn't exist in the previous configuration
        // Remove the unsupported extensions for the installed plugin

        const registryHostsData = Object.entries(source.hosts).reduce((accum, [hostID, hostData]) => {
          accum[hostID] = hostData;

          if (accum[hostID].extensions) {
            // Migrate extensions to those supported by the installed plugin
            const defaultHostExtentionsConfiguration = Object.fromEntries(supportedDefaultExtensionsConfiguration); // Select of current configuration the extension IDs that are supported in the installed plugin

            const currentHostConfiguration = _lodash.default.pick(accum[hostID].extensions, supportedDefaultExtensionsNames); // Merge the default extensions configuration with the configuration stored in the registry file


            accum[hostID].extensions = _lodash.default.merge(defaultHostExtentionsConfiguration, currentHostConfiguration);
          }

          return accum;
        }, {}); // Rebuild the registry file with the migrated host data (extensions are migrated to these supported by the installed plugin).

        await saveConfiguration(registryHostsData);
        (0, _logger.log)('initialize:checkwazuhRegistry', 'Migrated the registry file.', 'info');
      }
    }
  }; // Init function. Check for wazuh-registry.json file exists.


  const init = async () => {
    await checkWazuhRegistry();
  };

  const createKibanaTemplate = () => {
    (0, _logger.log)('initialize:createKibanaTemplate', `Creating template for ${PLUGIN_PLATFORM_INDEX}`, 'debug');

    try {
      _kibanaTemplate.pluginPlatformTemplate.template = PLUGIN_PLATFORM_INDEX + '*';
    } catch (error) {
      (0, _logger.log)('initialize:createKibanaTemplate', error.message || error);
      context.wazuh.logger.error('Exception: ' + error.message || error);
    }

    return context.core.opensearch.client.asInternalUser.indices.putTemplate({
      name: _constants.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME,
      order: 0,
      create: true,
      body: _kibanaTemplate.pluginPlatformTemplate
    });
  };

  const createEmptyKibanaIndex = async () => {
    try {
      (0, _logger.log)('initialize:createEmptyKibanaIndex', `Creating ${PLUGIN_PLATFORM_INDEX} index.`, 'info');
      await context.core.opensearch.client.asInternalUser.indices.create({
        index: PLUGIN_PLATFORM_INDEX
      });
      (0, _logger.log)('initialize:createEmptyKibanaIndex', `Successfully created ${PLUGIN_PLATFORM_INDEX} index.`, 'debug');
      await init();
    } catch (error) {
      return Promise.reject(new Error(`Error creating ${PLUGIN_PLATFORM_INDEX} index due to ${error.message || error}`));
    }
  };

  const fixKibanaTemplate = async () => {
    try {
      await createKibanaTemplate();
      (0, _logger.log)('initialize:fixKibanaTemplate', `Successfully created ${PLUGIN_PLATFORM_INDEX} template.`, 'debug');
      await createEmptyKibanaIndex();
    } catch (error) {
      return Promise.reject(new Error(`Error creating template for ${PLUGIN_PLATFORM_INDEX} due to ${error.message || error}`));
    }
  };

  const getTemplateByName = async () => {
    try {
      await context.core.opensearch.client.asInternalUser.indices.getTemplate({
        name: _constants.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME
      });
      (0, _logger.log)('initialize:getTemplateByName', `No need to create the ${PLUGIN_PLATFORM_INDEX} template, already exists.`, 'debug');
      await createEmptyKibanaIndex();
    } catch (error) {
      (0, _logger.log)('initialize:getTemplateByName', error.message || error);
      return fixKibanaTemplate();
    }
  }; // Does Kibana index exist?


  const checkKibanaStatus = async () => {
    try {
      const response = await context.core.opensearch.client.asInternalUser.indices.exists({
        index: PLUGIN_PLATFORM_INDEX
      });

      if (response.body) {
        // It exists, initialize!
        await init();
      } else {
        // No Kibana index created...
        (0, _logger.log)('initialize:checkKibanaStatus', `Not found ${PLUGIN_PLATFORM_INDEX} index`, 'info');
        await getTemplateByName();
      }
    } catch (error) {
      (0, _logger.log)('initialize:checkKibanaStatus', error.message || error);
      context.wazuh.logger.error(error.message || error);
    }
  }; // Wait until Elasticsearch js is ready


  const checkStatus = async () => {
    try {
      // TODO: wait until opensearch is ready?
      // await server.plugins.opensearch.waitUntilReady();
      return await checkKibanaStatus();
    } catch (error) {
      (0, _logger.log)('initialize:checkStatus', 'Waiting for opensearch plugin to be ready...', 'debug');
      setTimeout(() => checkStatus(), 3000);
    }
  }; // Check Kibana index and if it is prepared, start the initialization of Wazuh App.


  return checkStatus();
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbImpvYkluaXRpYWxpemVSdW4iLCJjb250ZXh0IiwiUExVR0lOX1BMQVRGT1JNX0lOREVYIiwic2VydmVyIiwiY29uZmlnIiwib3BlbnNlYXJjaERhc2hib2FyZHMiLCJpbmRleCIsIlBMVUdJTl9QTEFURk9STV9OQU1FIiwicGFja2FnZUpTT04iLCJyZXZpc2lvbiIsImNvbmZpZ3VyYXRpb25GaWxlIiwicGF0dGVybiIsImVycm9yIiwibWVzc2FnZSIsIndhenVoIiwibG9nZ2VyIiwicmFtIiwiTWF0aCIsImNlaWwiLCJzYXZlQ29uZmlndXJhdGlvbiIsImhvc3RzIiwiY29tbW9uRGF0ZSIsIkRhdGUiLCJ0b0lTT1N0cmluZyIsImNvbmZpZ3VyYXRpb24iLCJuYW1lIiwiUExVR0lOX0FQUF9OQU1FIiwidmVyc2lvbiIsImluc3RhbGxhdGlvbkRhdGUiLCJsYXN0UmVzdGFydCIsIkpTT04iLCJzdHJpbmdpZnkiLCJmcyIsIndyaXRlRmlsZVN5bmMiLCJXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRIIiwiY2hlY2tXYXp1aFJlZ2lzdHJ5IiwiZXhpc3RzU3luYyIsIldBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSCIsIkVycm9yIiwiUExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSIiwiUExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSX0dST1VQIiwic291cmNlIiwicGFyc2UiLCJyZWFkRmlsZVN5bmMiLCJpc1VwZ3JhZGVkQXBwIiwic3VwcG9ydGVkRGVmYXVsdEV4dGVuc2lvbnNDb25maWd1cmF0aW9uIiwiT2JqZWN0IiwiZW50cmllcyIsImZpbHRlciIsInNldHRpbmciLCJzdGFydHNXaXRoIiwibWFwIiwic2V0dGluZ1ZhbHVlIiwic3BsaXQiLCJzdXBwb3J0ZWREZWZhdWx0RXh0ZW5zaW9uc05hbWVzIiwicmVnaXN0cnlIb3N0c0RhdGEiLCJyZWR1Y2UiLCJhY2N1bSIsImhvc3RJRCIsImhvc3REYXRhIiwiZXh0ZW5zaW9ucyIsImRlZmF1bHRIb3N0RXh0ZW50aW9uc0NvbmZpZ3VyYXRpb24iLCJmcm9tRW50cmllcyIsImN1cnJlbnRIb3N0Q29uZmlndXJhdGlvbiIsIl8iLCJwaWNrIiwibWVyZ2UiLCJpbml0IiwiY3JlYXRlS2liYW5hVGVtcGxhdGUiLCJwbHVnaW5QbGF0Zm9ybVRlbXBsYXRlIiwidGVtcGxhdGUiLCJjb3JlIiwib3BlbnNlYXJjaCIsImNsaWVudCIsImFzSW50ZXJuYWxVc2VyIiwiaW5kaWNlcyIsInB1dFRlbXBsYXRlIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1RFTVBMQVRFX05BTUUiLCJvcmRlciIsImNyZWF0ZSIsImJvZHkiLCJjcmVhdGVFbXB0eUtpYmFuYUluZGV4IiwiUHJvbWlzZSIsInJlamVjdCIsImZpeEtpYmFuYVRlbXBsYXRlIiwiZ2V0VGVtcGxhdGVCeU5hbWUiLCJnZXRUZW1wbGF0ZSIsImNoZWNrS2liYW5hU3RhdHVzIiwicmVzcG9uc2UiLCJleGlzdHMiLCJjaGVja1N0YXR1cyIsInNldFRpbWVvdXQiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7OztBQXBCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBYU8sU0FBU0EsZ0JBQVQsQ0FBMEJDLE9BQTFCLEVBQW1DO0FBQ3hDLFFBQU1DLHFCQUFxQixHQUFHRCxPQUFPLENBQUNFLE1BQVIsQ0FBZUMsTUFBZixDQUFzQkMsb0JBQXRCLENBQTJDQyxLQUF6RTtBQUNBLG1CQUFJLFlBQUosRUFBbUIsR0FBRUMsK0JBQXFCLFdBQVVMLHFCQUFzQixFQUExRSxFQUE2RSxNQUE3RTtBQUNBLG1CQUFJLFlBQUosRUFBbUIsaUJBQWdCTSxpQkFBWUMsUUFBUyxFQUF4RCxFQUEyRCxNQUEzRDtBQUVBLE1BQUlDLGlCQUFpQixH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QUF2Qjs7QUFHQSxVQUFJc0YsUUFBUSxDQUFDUixJQUFiLEVBQW1CO0FBQ2pCO0FBQ0EsY0FBTWIsSUFBSSxFQUFWO0FBQ0QsT0FIRCxNQUdPO0FBQ0w7QUFDQSx5QkFDRSw4QkFERixFQUVHLGFBQVlqRSxxQkFBc0IsUUFGckMsRUFHRSxNQUhGO0FBS0EsY0FBTW1GLGlCQUFpQixFQUF2QjtBQUNEO0FBQ0YsS0FoQkQsQ0FnQkUsT0FBT3pFLEtBQVAsRUFBYztBQUNkLHVCQUFJLDhCQUFKLEVBQW9DQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQXJEO0FBQ0FYLE1BQUFBLE9BQU8sQ0FBQ2EsS0FBUixDQUFjQyxNQUFkLENBQXFCSCxLQUFyQixDQUEyQkEsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUE1QztBQUNEO0FBQ0YsR0FyQkQsQ0F4UHdDLENBK1F4Qzs7O0FBQ0EsUUFBTThFLFdBQVcsR0FBRyxZQUFZO0FBQzlCLFFBQUk7QUFDRjtBQUNBO0FBQ0EsYUFBTyxNQUFNSCxpQkFBaUIsRUFBOUI7QUFDRCxLQUpELENBSUUsT0FBTzNFLEtBQVAsRUFBYztBQUNkLHVCQUNFLHdCQURGLEVBRUUsOENBRkYsRUFHRSxPQUhGO0FBS0ErRSxNQUFBQSxVQUFVLENBQUMsTUFBTUQsV0FBVyxFQUFsQixFQUFzQixJQUF0QixDQUFWO0FBQ0Q7QUFDRixHQWJELENBaFJ3QyxDQStSeEM7OztBQUNBLFNBQU9BLFdBQVcsRUFBbEI7QUFDRCIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIGFwcCBpbml0aWFsaXphdGlvblxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCB7IGxvZyB9IGZyb20gJy4uLy4uL2xpYi9sb2dnZXInO1xuaW1wb3J0IHBhY2thZ2VKU09OIGZyb20gJy4uLy4uLy4uL3BhY2thZ2UuanNvbic7XG5pbXBvcnQgeyBwbHVnaW5QbGF0Zm9ybVRlbXBsYXRlIH0gZnJvbSAnLi4vLi4vaW50ZWdyYXRpb24tZmlsZXMva2liYW5hLXRlbXBsYXRlJztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi8uLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgdG90YWxtZW0gfSBmcm9tICdvcyc7XG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHsgV0FaVUhfREFUQV9DT05GSUdfUkVHSVNUUllfUEFUSCwgV0FaVUhfUExVR0lOX1BMQVRGT1JNX1RFTVBMQVRFX05BTUUsIFdBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSCwgUExVR0lOX1BMQVRGT1JNX05BTUUsIFBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUCwgUExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSLCBXQVpVSF9ERUZBVUxUX0FQUF9DT05GSUcsIFBMVUdJTl9BUFBfTkFNRSB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzIH0gZnJvbSAnLi4vLi4vbGliL2ZpbGVzeXN0ZW0nO1xuaW1wb3J0IF8gZnJvbSAnbG9kYXNoJztcbmltcG9ydCB7IGdldFNldHRpbmdEZWZhdWx0VmFsdWUsIGdldFNldHRpbmdzRGVmYXVsdCB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncyc7XG5cblxuZXhwb3J0IGZ1bmN0aW9uIGpvYkluaXRpYWxpemVSdW4oY29udGV4dCkge1xuICBjb25zdCBQTFVHSU5fUExBVEZPUk1fSU5ERVggPSBjb250ZXh0LnNlcnZlci5jb25maWcub3BlbnNlYXJjaERhc2hib2FyZHMuaW5kZXg7XG4gIGxvZygnaW5pdGlhbGl6ZScsIGAke1BMVUdJTl9QTEFURk9STV9OQU1FfSBpbmRleDogJHtQTFVHSU5fUExBVEZPUk1fSU5ERVh9YCwgJ2luZm8nKTtcbiAgbG9nKCdpbml0aWFsaXplJywgYEFwcCByZXZpc2lvbjogJHtwYWNrYWdlSlNPTi5yZXZpc2lvbn1gLCAnaW5mbycpO1xuXG4gIGxldCBjb25maWd1cmF0aW9uRmlsZSA9IHt9O1xuICBsZXQgcGF0dGVybiA9IG51bGw7XG4gIC8vIFJlYWQgY29uZmlnIGZyb20gcGFja2FnZS5qc29uIGFuZCB3YXp1aC55bWxcbiAgdHJ5IHtcbiAgICBjb25maWd1cmF0aW9uRmlsZSA9IGdldENvbmZpZ3VyYXRpb24oKTtcblxuICAgIHBhdHRlcm4gPVxuICAgICAgY29uZmlndXJhdGlvbkZpbGUgJiYgdHlwZW9mIGNvbmZpZ3VyYXRpb25GaWxlLnBhdHRlcm4gIT09ICd1bmRlZmluZWQnXG4gICAgICAgID8gY29uZmlndXJhdGlvbkZpbGUucGF0dGVyblxuICAgICAgICA6IGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3BhdHRlcm4nKTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBsb2coJ2luaXRpYWxpemUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihcbiAgICAgICdTb21ldGhpbmcgd2VudCB3cm9uZyB3aGlsZSByZWFkaW5nIHRoZSBjb25maWd1cmF0aW9uLicgKyAoZXJyb3IubWVzc2FnZSB8fCBlcnJvcilcbiAgICApO1xuICB9XG5cbiAgdHJ5IHtcbiAgICAvLyBSQU0gaW4gTUJcbiAgICBjb25zdCByYW0gPSBNYXRoLmNlaWwodG90YWxtZW0oKSAvIDEwMjQgLyAxMDI0KTtcbiAgICBsb2coJ2luaXRpYWxpemUnLCBgVG90YWwgUkFNOiAke3JhbX1NQmAsICdpbmZvJyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKFxuICAgICAgJ2luaXRpYWxpemUnLFxuICAgICAgYENvdWxkIG5vdCBjaGVjayB0b3RhbCBSQU0gZHVlIHRvOiAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICk7XG4gIH1cblxuICAvLyBTYXZlIFdhenVoIEFwcCBzZXR1cFxuICBjb25zdCBzYXZlQ29uZmlndXJhdGlvbiA9IGFzeW5jIChob3N0cyA9IHt9KSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGNvbW1vbkRhdGUgPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG5cbiAgICAgIGNvbnN0IGNvbmZpZ3VyYXRpb24gPSB7XG4gICAgICAgIG5hbWU6IFBMVUdJTl9BUFBfTkFNRSxcbiAgICAgICAgJ2FwcC12ZXJzaW9uJzogcGFja2FnZUpTT04udmVyc2lvbixcbiAgICAgICAgcmV2aXNpb246IHBhY2thZ2VKU09OLnJldmlzaW9uLFxuICAgICAgICBpbnN0YWxsYXRpb25EYXRlOiBjb21tb25EYXRlLFxuICAgICAgICBsYXN0UmVzdGFydDogY29tbW9uRGF0ZSxcbiAgICAgICAgaG9zdHNcbiAgICAgIH07XG4gICAgICB0cnkge1xuICAgICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgICAgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzKCdjb25maWcnKTtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICdpbml0aWFsaXplOnNhdmVDb25maWd1cmF0aW9uJyxcbiAgICAgICAgICBgU2F2aW5nIGNvbmZpZ3VyYXRpb24gaW4gcmVnaXN0cnkgZmlsZTogJHtKU09OLnN0cmluZ2lmeShjb25maWd1cmF0aW9uKX1gLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgICAgYXdhaXQgZnMud3JpdGVGaWxlU3luYyhXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRILCBKU09OLnN0cmluZ2lmeShjb25maWd1cmF0aW9uKSwgJ3V0ZjgnKTtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICdpbml0aWFsaXplOnNhdmVDb25maWd1cmF0aW9uJyxcbiAgICAgICAgICAnV2F6dWggY29uZmlndXJhdGlvbiByZWdpc3RyeSBzYXZlZC4nLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGxvZygnaW5pdGlhbGl6ZTpzYXZlQ29uZmlndXJhdGlvbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAnQ291bGQgbm90IGNyZWF0ZSBXYXp1aCBjb25maWd1cmF0aW9uIHJlZ2lzdHJ5J1xuICAgICAgICApO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ2luaXRpYWxpemU6c2F2ZUNvbmZpZ3VyYXRpb24nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKFxuICAgICAgICAnRXJyb3IgY3JlYXRpbmcgd2F6dWgtcmVnaXN0cnkuanNvbiBmaWxlLidcbiAgICAgICk7XG4gICAgfVxuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgdGhlIC53YXp1aC1yZWdpc3RyeS5qc29uIGZpbGUgZXhpc3RzOlxuICAgKiAtIHllczogY2hlY2sgdGhlIHBsdWdpbiB2ZXJzaW9uIGFuZCByZXZpc2lvbiBtYXRjaCB0aGUgdmFsdWVzIHN0b3JlZCBpbiB0aGUgcmVnaXN0cnkgZmlsZS5cbiAgICogIElmIG5vdCwgdGhlbiBpdCBtaWdyYXRlcyB0aGUgZGF0YSByZWJ1aWxkaW5nIHRoZSByZWdpc3RyeSBmaWxlLlxuICAgKiAtIG5vOiBjcmVhdGUgdGhlIGZpbGUgd2l0aCBlbXB0eSBob3N0c1xuICAgKi9cbiAgY29uc3QgY2hlY2tXYXp1aFJlZ2lzdHJ5ID0gYXN5bmMgKCkgPT4ge1xuICAgIGxvZyhcbiAgICAgICdpbml0aWFsaXplOmNoZWNrd2F6dWhSZWdpc3RyeScsXG4gICAgICAnQ2hlY2tpbmcgd2F6dWgtcmVnaXN0cnkuanNvbiBmaWxlLicsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgIGlmICghZnMuZXhpc3RzU3luYyhXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX0FCU09MVVRFX1BBVEgpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYFRoZSBkYXRhIGRpcmVjdG9yeSBpcyBtaXNzaW5nIGluIHRoZSAke1BMVUdJTl9QTEFURk9STV9OQU1FfSByb290IGluc3RhbGF0aW9uLiBDcmVhdGUgdGhlIGRpcmVjdG9yeSBpbiAke1dBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSH0gYW5kIGdpdmUgaXQgdGhlIHJlcXVpcmVkIHBlcm1pc3Npb25zIChzdWRvIG1rZGlyICR7V0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9BQlNPTFVURV9QQVRIfTtzdWRvIGNob3duIC1SICR7UExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSfToke1BMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUH0gJHtXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX0FCU09MVVRFX1BBVEh9KS4gQWZ0ZXIgcmVzdGFydCB0aGUgJHtQTFVHSU5fUExBVEZPUk1fTkFNRX0gc2VydmljZS5gKTtcbiAgICB9O1xuXG4gICAgaWYgKCFmcy5leGlzdHNTeW5jKFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEgpKSB7XG4gICAgICBsb2coXG4gICAgICAgICdpbml0aWFsaXplOmNoZWNrd2F6dWhSZWdpc3RyeScsXG4gICAgICAgICd3YXp1aC1yZWdpc3RyeS5qc29uIGZpbGUgZG9lcyBub3QgZXhpc3QuIEluaXRpYWxpemluZyBjb25maWd1cmF0aW9uLicsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG5cbiAgICAgIC8vIENyZWF0ZSB0aGUgYXBwIHJlZ2lzdHJ5IGZpbGUgZm9yIHRoZSB2ZXJ5IGZpcnN0IHRpbWVcbiAgICAgIGF3YWl0IHNhdmVDb25maWd1cmF0aW9uKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIElmIHRoaXMgZnVuY3Rpb24gZmFpbHMsIGl0IHRocm93cyBhbiBleGNlcHRpb25cbiAgICAgIGNvbnN0IHNvdXJjZSA9IEpTT04ucGFyc2UoZnMucmVhZEZpbGVTeW5jKFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEgsICd1dGY4JykpO1xuXG4gICAgICAvLyBDaGVjayBpZiB0aGUgc3RvcmVkIHJldmlzaW9uIGRpZmZlcnMgZnJvbSB0aGUgcGFja2FnZS5qc29uIHJldmlzaW9uXG4gICAgICBjb25zdCBpc1VwZ3JhZGVkQXBwID0gcGFja2FnZUpTT04ucmV2aXNpb24gIT09IHNvdXJjZS5yZXZpc2lvbiB8fCBwYWNrYWdlSlNPTi52ZXJzaW9uICE9PSBzb3VyY2VbJ2FwcC12ZXJzaW9uJ107XG5cbiAgICAgIC8vIFJlYnVpbGQgdGhlIHJlZ2lzdHJ5IGZpbGUgaWYgcmV2aXNpb24gb3IgdmVyc2lvbiBmaWVsZHMgYXJlIGRpZmZlcmVudHNcbiAgICAgIGlmIChpc1VwZ3JhZGVkQXBwKSB7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAnaW5pdGlhbGl6ZTpjaGVja3dhenVoUmVnaXN0cnknLFxuICAgICAgICAgICdXYXp1aCBhcHAgcmV2aXNpb24gb3IgdmVyc2lvbiBjaGFuZ2VkLCByZWdlbmVyYXRpbmcgd2F6dWgtcmVnaXN0cnkuanNvbi4nLFxuICAgICAgICAgICdpbmZvJ1xuICAgICAgICApO1xuXG4gICAgICAgIC8vIFJlYnVpbGQgdGhlIHJlZ2lzdHJ5IGZpbGUgYHdhenVoLXJlZ2lzdHJ5Lmpzb25gXG5cbiAgICAgICAgLy8gR2V0IHRoZSBzdXBwb3J0ZWQgZXh0ZW5zaW9ucyBmb3IgdGhlIGluc3RhbGxlZCBwbHVnaW5cbiAgICAgICAgY29uc3Qgc3VwcG9ydGVkRGVmYXVsdEV4dGVuc2lvbnNDb25maWd1cmF0aW9uID0gT2JqZWN0LmVudHJpZXMoZ2V0U2V0dGluZ3NEZWZhdWx0KCkpXG4gICAgICAgICAgLmZpbHRlcigoW3NldHRpbmddKSA9PiBzZXR0aW5nLnN0YXJ0c1dpdGgoJ2V4dGVuc2lvbnMuJykpXG4gICAgICAgICAgLm1hcCgoW3NldHRpbmcsIHNldHRpbmdWYWx1ZV0pID0+IHtcbiAgICAgICAgICAgIHJldHVybiBbc2V0dGluZy5zcGxpdCgnLicpWzFdLCBzZXR0aW5nVmFsdWVdO1xuICAgICAgICAgIH0pO1xuXG4gICAgICAgIC8vIEdldCB0aGUgc3VwcG9ydGVkIGV4dGVuc2lvbnMgYnkgSURcbiAgICAgICAgY29uc3Qgc3VwcG9ydGVkRGVmYXVsdEV4dGVuc2lvbnNOYW1lcyA9IHN1cHBvcnRlZERlZmF1bHRFeHRlbnNpb25zQ29uZmlndXJhdGlvbi5tYXAoKFtzZXR0aW5nXSkgPT4gc2V0dGluZyk7XG5cbiAgICAgICAgLy8gR2VuZXJhdGUgdGhlIGhvc3RzIGRhdGEsIG1pZ3JhdGluZyB0aGUgZXh0ZW5zaW9ucy5cbiAgICAgICAgLy8gS2VlcCB0aGUgc3VwcG9ydGVkIGFuZCBleGlzdGVudCBleHRlbnNpb25zIGZvciB0aGUgaW5zdGFsbGVkIHBsdWdpbiB3aXRoIHRoZSBjb25maWd1cmF0ZWQgdmFsdWVcbiAgICAgICAgLy8gQWRkIHRoZSBleHRlbnNpb25zIHdpdGggZGVmYXVsdCB2YWx1ZXMgdGhhdCBkaWRuJ3QgZXhpc3QgaW4gdGhlIHByZXZpb3VzIGNvbmZpZ3VyYXRpb25cbiAgICAgICAgLy8gUmVtb3ZlIHRoZSB1bnN1cHBvcnRlZCBleHRlbnNpb25zIGZvciB0aGUgaW5zdGFsbGVkIHBsdWdpblxuICAgICAgICBjb25zdCByZWdpc3RyeUhvc3RzRGF0YSA9IE9iamVjdC5lbnRyaWVzKHNvdXJjZS5ob3N0cykucmVkdWNlKChhY2N1bSwgW2hvc3RJRCwgaG9zdERhdGFdKSA9PiB7XG4gICAgICAgICAgYWNjdW1baG9zdElEXSA9IGhvc3REYXRhO1xuICAgICAgICAgIGlmIChhY2N1bVtob3N0SURdLmV4dGVuc2lvbnMpIHtcbiAgICAgICAgICAgIC8vIE1pZ3JhdGUgZXh0ZW5zaW9ucyB0byB0aG9zZSBzdXBwb3J0ZWQgYnkgdGhlIGluc3RhbGxlZCBwbHVnaW5cbiAgICAgICAgICAgIGNvbnN0IGRlZmF1bHRIb3N0RXh0ZW50aW9uc0NvbmZpZ3VyYXRpb24gPSBPYmplY3QuZnJvbUVudHJpZXMoc3VwcG9ydGVkRGVmYXVsdEV4dGVuc2lvbnNDb25maWd1cmF0aW9uKTtcbiAgICAgICAgICAgIC8vIFNlbGVjdCBvZiBjdXJyZW50IGNvbmZpZ3VyYXRpb24gdGhlIGV4dGVuc2lvbiBJRHMgdGhhdCBhcmUgc3VwcG9ydGVkIGluIHRoZSBpbnN0YWxsZWQgcGx1Z2luXG4gICAgICAgICAgICBjb25zdCBjdXJyZW50SG9zdENvbmZpZ3VyYXRpb24gPSBfLnBpY2soYWNjdW1baG9zdElEXS5leHRlbnNpb25zLCBzdXBwb3J0ZWREZWZhdWx0RXh0ZW5zaW9uc05hbWVzKTtcbiAgICAgICAgICAgIC8vIE1lcmdlIHRoZSBkZWZhdWx0IGV4dGVuc2lvbnMgY29uZmlndXJhdGlvbiB3aXRoIHRoZSBjb25maWd1cmF0aW9uIHN0b3JlZCBpbiB0aGUgcmVnaXN0cnkgZmlsZVxuICAgICAgICAgICAgYWNjdW1baG9zdElEXS5leHRlbnNpb25zID0gXy5tZXJnZShkZWZhdWx0SG9zdEV4dGVudGlvbnNDb25maWd1cmF0aW9uLCBjdXJyZW50SG9zdENvbmZpZ3VyYXRpb24pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gYWNjdW07XG4gICAgICAgIH0sIHt9KTtcblxuICAgICAgICAvLyBSZWJ1aWxkIHRoZSByZWdpc3RyeSBmaWxlIHdpdGggdGhlIG1pZ3JhdGVkIGhvc3QgZGF0YSAoZXh0ZW5zaW9ucyBhcmUgbWlncmF0ZWQgdG8gdGhlc2Ugc3VwcG9ydGVkIGJ5IHRoZSBpbnN0YWxsZWQgcGx1Z2luKS5cbiAgICAgICAgYXdhaXQgc2F2ZUNvbmZpZ3VyYXRpb24ocmVnaXN0cnlIb3N0c0RhdGEpO1xuXG4gICAgICAgIGxvZyhcbiAgICAgICAgICAnaW5pdGlhbGl6ZTpjaGVja3dhenVoUmVnaXN0cnknLFxuICAgICAgICAgICdNaWdyYXRlZCB0aGUgcmVnaXN0cnkgZmlsZS4nLFxuICAgICAgICAgICdpbmZvJ1xuICAgICAgICApO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICAvLyBJbml0IGZ1bmN0aW9uLiBDaGVjayBmb3Igd2F6dWgtcmVnaXN0cnkuanNvbiBmaWxlIGV4aXN0cy5cbiAgY29uc3QgaW5pdCA9IGFzeW5jICgpID0+IHtcbiAgICBhd2FpdCBjaGVja1dhenVoUmVnaXN0cnkoKTtcbiAgfTtcblxuICBjb25zdCBjcmVhdGVLaWJhbmFUZW1wbGF0ZSA9ICgpID0+IHtcbiAgICBsb2coXG4gICAgICAnaW5pdGlhbGl6ZTpjcmVhdGVLaWJhbmFUZW1wbGF0ZScsXG4gICAgICBgQ3JlYXRpbmcgdGVtcGxhdGUgZm9yICR7UExVR0lOX1BMQVRGT1JNX0lOREVYfWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgIHRyeSB7XG4gICAgICBwbHVnaW5QbGF0Zm9ybVRlbXBsYXRlLnRlbXBsYXRlID0gUExVR0lOX1BMQVRGT1JNX0lOREVYICsgJyonO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ2luaXRpYWxpemU6Y3JlYXRlS2liYW5hVGVtcGxhdGUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKFxuICAgICAgICAnRXhjZXB0aW9uOiAnICsgZXJyb3IubWVzc2FnZSB8fCBlcnJvclxuICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gY29udGV4dC5jb3JlLm9wZW5zZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMucHV0VGVtcGxhdGUoe1xuICAgICAgbmFtZTogV0FaVUhfUExVR0lOX1BMQVRGT1JNX1RFTVBMQVRFX05BTUUsXG4gICAgICBvcmRlcjogMCxcbiAgICAgIGNyZWF0ZTogdHJ1ZSxcbiAgICAgIGJvZHk6IHBsdWdpblBsYXRmb3JtVGVtcGxhdGVcbiAgICB9KTtcbiAgfTtcblxuICBjb25zdCBjcmVhdGVFbXB0eUtpYmFuYUluZGV4ID0gYXN5bmMgKCkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coXG4gICAgICAgICdpbml0aWFsaXplOmNyZWF0ZUVtcHR5S2liYW5hSW5kZXgnLFxuICAgICAgICBgQ3JlYXRpbmcgJHtQTFVHSU5fUExBVEZPUk1fSU5ERVh9IGluZGV4LmAsXG4gICAgICAgICdpbmZvJ1xuICAgICAgKTtcbiAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLmNyZWF0ZSh7XG4gICAgICAgIGluZGV4OiBQTFVHSU5fUExBVEZPUk1fSU5ERVhcbiAgICAgIH0pO1xuICAgICAgbG9nKFxuICAgICAgICAnaW5pdGlhbGl6ZTpjcmVhdGVFbXB0eUtpYmFuYUluZGV4JyxcbiAgICAgICAgYFN1Y2Nlc3NmdWxseSBjcmVhdGVkICR7UExVR0lOX1BMQVRGT1JNX0lOREVYfSBpbmRleC5gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgYXdhaXQgaW5pdCgpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgIG5ldyBFcnJvcihcbiAgICAgICAgICBgRXJyb3IgY3JlYXRpbmcgJHtQTFVHSU5fUExBVEZPUk1fSU5ERVhcbiAgICAgICAgICB9IGluZGV4IGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICAgICApXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCBmaXhLaWJhbmFUZW1wbGF0ZSA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgY3JlYXRlS2liYW5hVGVtcGxhdGUoKTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ2luaXRpYWxpemU6Zml4S2liYW5hVGVtcGxhdGUnLFxuICAgICAgICBgU3VjY2Vzc2Z1bGx5IGNyZWF0ZWQgJHtQTFVHSU5fUExBVEZPUk1fSU5ERVh9IHRlbXBsYXRlLmAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBhd2FpdCBjcmVhdGVFbXB0eUtpYmFuYUluZGV4KCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcbiAgICAgICAgbmV3IEVycm9yKFxuICAgICAgICAgIGBFcnJvciBjcmVhdGluZyB0ZW1wbGF0ZSBmb3IgJHtQTFVHSU5fUExBVEZPUk1fSU5ERVhcbiAgICAgICAgICB9IGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YFxuICAgICAgICApXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCBnZXRUZW1wbGF0ZUJ5TmFtZSA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgY29udGV4dC5jb3JlLm9wZW5zZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZ2V0VGVtcGxhdGUoe1xuICAgICAgICBuYW1lOiBXQVpVSF9QTFVHSU5fUExBVEZPUk1fVEVNUExBVEVfTkFNRVxuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICdpbml0aWFsaXplOmdldFRlbXBsYXRlQnlOYW1lJyxcbiAgICAgICAgYE5vIG5lZWQgdG8gY3JlYXRlIHRoZSAke1BMVUdJTl9QTEFURk9STV9JTkRFWH0gdGVtcGxhdGUsIGFscmVhZHkgZXhpc3RzLmAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBhd2FpdCBjcmVhdGVFbXB0eUtpYmFuYUluZGV4KCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnaW5pdGlhbGl6ZTpnZXRUZW1wbGF0ZUJ5TmFtZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIGZpeEtpYmFuYVRlbXBsYXRlKCk7XG4gICAgfVxuICB9O1xuXG4gIC8vIERvZXMgS2liYW5hIGluZGV4IGV4aXN0P1xuICBjb25zdCBjaGVja0tpYmFuYVN0YXR1cyA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LmNvcmUub3BlbnNlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgICBpbmRleDogUExVR0lOX1BMQVRGT1JNX0lOREVYXG4gICAgICB9KTtcbiAgICAgIGlmIChyZXNwb25zZS5ib2R5KSB7XG4gICAgICAgIC8vIEl0IGV4aXN0cywgaW5pdGlhbGl6ZSFcbiAgICAgICAgYXdhaXQgaW5pdCgpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gTm8gS2liYW5hIGluZGV4IGNyZWF0ZWQuLi5cbiAgICAgICAgbG9nKFxuICAgICAgICAgICdpbml0aWFsaXplOmNoZWNrS2liYW5hU3RhdHVzJyxcbiAgICAgICAgICBgTm90IGZvdW5kICR7UExVR0lOX1BMQVRGT1JNX0lOREVYfSBpbmRleGAsXG4gICAgICAgICAgJ2luZm8nXG4gICAgICAgICk7XG4gICAgICAgIGF3YWl0IGdldFRlbXBsYXRlQnlOYW1lKCk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnaW5pdGlhbGl6ZTpjaGVja0tpYmFuYVN0YXR1cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgfVxuICB9O1xuXG4gIC8vIFdhaXQgdW50aWwgRWxhc3RpY3NlYXJjaCBqcyBpcyByZWFkeVxuICBjb25zdCBjaGVja1N0YXR1cyA9IGFzeW5jICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgLy8gVE9ETzogd2FpdCB1bnRpbCBvcGVuc2VhcmNoIGlzIHJlYWR5P1xuICAgICAgLy8gYXdhaXQgc2VydmVyLnBsdWdpbnMub3BlbnNlYXJjaC53YWl0VW50aWxSZWFkeSgpO1xuICAgICAgcmV0dXJuIGF3YWl0IGNoZWNrS2liYW5hU3RhdHVzKCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ2luaXRpYWxpemU6Y2hlY2tTdGF0dXMnLFxuICAgICAgICAnV2FpdGluZyBmb3Igb3BlbnNlYXJjaCBwbHVnaW4gdG8gYmUgcmVhZHkuLi4nLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgc2V0VGltZW91dCgoKSA9PiBjaGVja1N0YXR1cygpLCAzMDAwKTtcbiAgICB9XG4gIH07XG5cbiAgLy8gQ2hlY2sgS2liYW5hIGluZGV4IGFuZCBpZiBpdCBpcyBwcmVwYXJlZCwgc3RhcnQgdGhlIGluaXRpYWxpemF0aW9uIG9mIFdhenVoIEFwcC5cbiAgcmV0dXJuIGNoZWNrU3RhdHVzKCk7XG59XG4iXX0=