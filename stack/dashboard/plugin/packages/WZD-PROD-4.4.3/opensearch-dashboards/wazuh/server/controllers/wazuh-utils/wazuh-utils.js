"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhUtilsCtrl = void 0;

var _errorResponse = require("../../lib/error-response");

var _getConfiguration = require("../../lib/get-configuration");

var _readLastLines = require("read-last-lines");

var _updateConfiguration = require("../../lib/update-configuration");

var _jwtDecode = _interopRequireDefault(require("jwt-decode"));

var _constants = require("../../../common/constants");

var _manageHosts = require("../../lib/manage-hosts");

var _cookie = require("../../lib/cookie");

var _fs = _interopRequireDefault(require("fs"));

var _path = _interopRequireDefault(require("path"));

var _filesystem = require("../../lib/filesystem");

var _glob = _interopRequireDefault(require("glob"));

var _fileExtension = require("../../../common/services/file-extension");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const updateConfigurationFile = new _updateConfiguration.UpdateConfigurationFile(); // TODO: these controllers have no logs. We should include them.

class WazuhUtilsCtrl {
  /**
   * Constructor
   * @param {*} server
   */
  constructor() {
    _defineProperty(this, "updateConfigurationFile", this.routeDecoratorProtectedAdministratorRoleValidToken(async (context, request, response) => {
      let requiresRunningHealthCheck = false,
          requiresReloadingBrowserTab = false,
          requiresRestartingPluginPlatform = false; // Plugin settings configurables in the configuration file.

      const pluginSettingsConfigurableFile = Object.keys(request.body).filter(pluginSettingKey => _constants.PLUGIN_SETTINGS[pluginSettingKey].isConfigurableFromFile).reduce((accum, pluginSettingKey) => ({ ...accum,
        [pluginSettingKey]: request.body[pluginSettingKey]
      }), {});

      if (Object.keys(pluginSettingsConfigurableFile).length) {
        // Update the configuration file.
        await updateConfigurationFile.updateConfiguration(pluginSettingsConfigurableFile);
        requiresRunningHealthCheck = Object.keys(pluginSettingsConfigurableFile).some(pluginSettingKey => Boolean(_constants.PLUGIN_SETTINGS[pluginSettingKey].requiresRunningHealthCheck)) || requiresRunningHealthCheck;
        requiresReloadingBrowserTab = Object.keys(pluginSettingsConfigurableFile).some(pluginSettingKey => Boolean(_constants.PLUGIN_SETTINGS[pluginSettingKey].requiresReloadingBrowserTab)) || requiresReloadingBrowserTab;
        requiresRestartingPluginPlatform = Object.keys(pluginSettingsConfigurableFile).some(pluginSettingKey => Boolean(_constants.PLUGIN_SETTINGS[pluginSettingKey].requiresRestartingPluginPlatform)) || requiresRestartingPluginPlatform;
      }

      ;
      return response.ok({
        body: {
          data: {
            requiresRunningHealthCheck,
            requiresReloadingBrowserTab,
            requiresRestartingPluginPlatform,
            updatedConfiguration: pluginSettingsConfigurableFile
          }
        }
      });
    }, 3021));

    _defineProperty(this, "uploadFile", this.routeDecoratorProtectedAdministratorRoleValidToken(async (context, request, response) => {
      const {
        key
      } = request.params;
      const {
        file: bufferFile
      } = request.body;
      const pluginSetting = _constants.PLUGIN_SETTINGS[key]; // Check file extension

      const fileExtension = (0, _fileExtension.getFileExtensionFromBuffer)(bufferFile); // Check if the extension is valid for the setting.

      if (!pluginSetting.options.file.extensions.includes(`.${fileExtension}`)) {
        return response.badRequest({
          body: `File extension is not valid for setting [${key}] setting. Allowed file extensions: ${pluginSetting.options.file.extensions.join(', ')}`
        });
      }

      ;
      const fileNamePath = `${key}.${fileExtension}`; // Create target directory

      const targetDirectory = _path.default.join(__dirname, '../../..', pluginSetting.options.file.store.relativePathFileSystem);

      (0, _filesystem.createDirectoryIfNotExists)(targetDirectory); // Get the files related to the setting and remove them

      const files = _glob.default.sync(_path.default.join(targetDirectory, `${key}.*`));

      files.forEach(_fs.default.unlinkSync); // Store the file in the target directory.

      _fs.default.writeFileSync(_path.default.join(targetDirectory, fileNamePath), bufferFile); // Update the setting in the configuration cache


      const pluginSettingValue = pluginSetting.options.file.store.resolveStaticURL(fileNamePath);
      await updateConfigurationFile.updateConfiguration({
        [key]: pluginSettingValue
      });
      return response.ok({
        body: {
          data: {
            requiresRunningHealthCheck: Boolean(pluginSetting.requiresRunningHealthCheck),
            requiresReloadingBrowserTab: Boolean(pluginSetting.requiresReloadingBrowserTab),
            requiresRestartingPluginPlatform: Boolean(pluginSetting.requiresRestartingPluginPlatform),
            updatedConfiguration: {
              [key]: pluginSettingValue
            }
          }
        }
      });
    }, 3022));

    _defineProperty(this, "deleteFile", this.routeDecoratorProtectedAdministratorRoleValidToken(async (context, request, response) => {
      const {
        key
      } = request.params;
      const pluginSetting = _constants.PLUGIN_SETTINGS[key]; // Get the files related to the setting and remove them

      const targetDirectory = _path.default.join(__dirname, '../../..', pluginSetting.options.file.store.relativePathFileSystem);

      const files = _glob.default.sync(_path.default.join(targetDirectory, `${key}.*`));

      files.forEach(_fs.default.unlinkSync); // Update the setting in the configuration cache

      const pluginSettingValue = pluginSetting.defaultValue;
      await updateConfigurationFile.updateConfiguration({
        [key]: pluginSettingValue
      });
      return response.ok({
        body: {
          message: 'All files were removed and the configuration file was updated.',
          data: {
            requiresRunningHealthCheck: Boolean(pluginSetting.requiresRunningHealthCheck),
            requiresReloadingBrowserTab: Boolean(pluginSetting.requiresReloadingBrowserTab),
            requiresRestartingPluginPlatform: Boolean(pluginSetting.requiresRestartingPluginPlatform),
            updatedConfiguration: {
              [key]: pluginSettingValue
            }
          }
        }
      });
    }, 3023));

    this.manageHosts = new _manageHosts.ManageHosts();
  }
  /**
   * Returns the wazuh.yml file parsed
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} Configuration File or ErrorResponse
   */


  getConfigurationFile(context, request, response) {
    try {
      const configFile = (0, _getConfiguration.getConfiguration)();
      return response.ok({
        body: {
          statusCode: 200,
          error: 0,
          data: configFile || {}
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3019, 500, response);
    }
  }
  /**
   * Returns the wazuh.yml file in raw
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} Configuration File or ErrorResponse
   */


  /**
   * Returns Wazuh app logs
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<String>} app logs or ErrorResponse
   */
  async getAppLogs(context, request, response) {
    try {
      const lastLogs = await (0, _readLastLines.read)(_constants.WAZUH_DATA_LOGS_RAW_PATH, 50);
      const spliterLog = lastLogs.split('\n');
      return spliterLog && Array.isArray(spliterLog) ? response.ok({
        body: {
          error: 0,
          lastLogs: spliterLog.filter(item => typeof item === 'string' && item.length)
        }
      }) : response.ok({
        error: 0,
        lastLogs: []
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3036, 500, response);
    }
  }
  /**
   * Upload a file
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} Configuration File or ErrorResponse
   */


  routeDecoratorProtectedAdministratorRoleValidToken(routeHandler, errorCode) {
    return async (context, request, response) => {
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
        const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', '/', {}, {
          apiHostID
        });

        if (responseTokenIsWorking.status !== 200) {
          return (0, _errorResponse.ErrorResponse)('Token is not valid', 401, 401, response);
        }

        ;
        return await routeHandler(context, request, response);
      } catch (error) {
        return (0, _errorResponse.ErrorResponse)(error.message || error, errorCode, 500, response);
      }
    };
  }

}

exports.WazuhUtilsCtrl = WazuhUtilsCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLXV0aWxzLnRzIl0sIm5hbWVzIjpbInVwZGF0ZUNvbmZpZ3VyYXRpb25GaWxlIiwiVXBkYXRlQ29uZmlndXJhdGlvbkZpbGUiLCJXYXp1aFV0aWxzQ3RybCIsImNvbnN0cnVjdG9yIiwicm91dGVEZWNvcmF0b3JQcm90ZWN0ZWRBZG1pbmlzdHJhdG9yUm9sZVZhbGlkVG9rZW4iLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwicmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2siLCJyZXF1aXJlc1JlbG9hZGluZ0Jyb3dzZXJUYWIiLCJyZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybSIsInBsdWdpblNldHRpbmdzQ29uZmlndXJhYmxlRmlsZSIsIk9iamVjdCIsImtleXMiLCJib2R5IiwiZmlsdGVyIiwicGx1Z2luU2V0dGluZ0tleSIsIlBMVUdJTl9TRVRUSU5HUyIsImlzQ29uZmlndXJhYmxlRnJvbUZpbGUiLCJyZWR1Y2UiLCJhY2N1bSIsImxlbmd0aCIsInVwZGF0ZUNvbmZpZ3VyYXRpb24iLCJzb21lIiwiQm9vbGVhbiIsIm9rIiwiZGF0YSIsInVwZGF0ZWRDb25maWd1cmF0aW9uIiwia2V5IiwicGFyYW1zIiwiZmlsZSIsImJ1ZmZlckZpbGUiLCJwbHVnaW5TZXR0aW5nIiwiZmlsZUV4dGVuc2lvbiIsIm9wdGlvbnMiLCJleHRlbnNpb25zIiwiaW5jbHVkZXMiLCJiYWRSZXF1ZXN0Iiwiam9pbiIsImZpbGVOYW1lUGF0aCIsInRhcmdldERpcmVjdG9yeSIsInBhdGgiLCJfX2Rpcm5hbWUiLCJzdG9yZSIsInJlbGF0aXZlUGF0aEZpbGVTeXN0ZW0iLCJmaWxlcyIsImdsb2IiLCJzeW5jIiwiZm9yRWFjaCIsImZzIiwidW5saW5rU3luYyIsIndyaXRlRmlsZVN5bmMiLCJwbHVnaW5TZXR0aW5nVmFsdWUiLCJyZXNvbHZlU3RhdGljVVJMIiwiZGVmYXVsdFZhbHVlIiwibWVzc2FnZSIsIm1hbmFnZUhvc3RzIiwiTWFuYWdlSG9zdHMiLCJnZXRDb25maWd1cmF0aW9uRmlsZSIsImNvbmZpZ0ZpbGUiLCJzdGF0dXNDb2RlIiwiZXJyb3IiLCJnZXRBcHBMb2dzIiwibGFzdExvZ3MiLCJXQVpVSF9EQVRBX0xPR1NfUkFXX1BBVEgiLCJzcGxpdGVyTG9nIiwic3BsaXQiLCJBcnJheSIsImlzQXJyYXkiLCJpdGVtIiwicm91dGVIYW5kbGVyIiwiZXJyb3JDb2RlIiwidG9rZW4iLCJoZWFkZXJzIiwiY29va2llIiwiZGVjb2RlZFRva2VuIiwicmJhY19yb2xlcyIsIldBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9JRCIsImFwaUhvc3RJRCIsInJlc3BvbnNlVG9rZW5Jc1dvcmtpbmciLCJ3YXp1aCIsImFwaSIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJzdGF0dXMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFhQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFFQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7Ozs7O0FBRUEsTUFBTUEsdUJBQXVCLEdBQUcsSUFBSUMsNENBQUosRUFBaEMsQyxDQUVBOztBQUNPLE1BQU1DLGNBQU4sQ0FBcUI7QUFDMUI7QUFDRjtBQUNBO0FBQ0E7QUFDRUMsRUFBQUEsV0FBVyxHQUFHO0FBQUEscURBa0NZLEtBQUtDLGtEQUFMLENBQ3hCLE9BQU9DLE9BQVAsRUFBdUNDLE9BQXZDLEVBQTZFQyxRQUE3RSxLQUErSDtBQUU3SCxVQUFJQywwQkFBbUMsR0FBRyxLQUExQztBQUFBLFVBQ0VDLDJCQUFvQyxHQUFHLEtBRHpDO0FBQUEsVUFFRUMsZ0NBQXlDLEdBQUcsS0FGOUMsQ0FGNkgsQ0FNN0g7O0FBQ0EsWUFBTUMsOEJBQThCLEdBQUdDLE1BQU0sQ0FBQ0MsSUFBUCxDQUFZUCxPQUFPLENBQUNRLElBQXBCLEVBQ3BDQyxNQURvQyxDQUM3QkMsZ0JBQWdCLElBQUlDLDJCQUFnQkQsZ0JBQWhCLEVBQWtDRSxzQkFEekIsRUFFcENDLE1BRm9DLENBRTdCLENBQUNDLEtBQUQs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LFNBWkMsQ0FhRjs7QUFDQSxjQUFNdUUsU0FBUyxHQUFHLGtDQUFxQnhFLE9BQU8sQ0FBQ21FLE9BQVIsQ0FBZ0JDLE1BQXJDLEVBQTZDLFFBQTdDLENBQWxCOztBQUNBLFlBQUksQ0FBQ0ksU0FBTCxFQUFnQjtBQUNkLGlCQUFPLGtDQUFjLG9CQUFkLEVBQW9DLEdBQXBDLEVBQXlDLEdBQXpDLEVBQThDdkUsUUFBOUMsQ0FBUDtBQUNEOztBQUFBO0FBQ0QsY0FBTXdFLHNCQUFzQixHQUFHLE1BQU0xRSxPQUFPLENBQUMyRSxLQUFSLENBQWNDLEdBQWQsQ0FBa0JDLE1BQWxCLENBQXlCQyxhQUF6QixDQUF1QzdFLE9BQXZDLENBQStDLEtBQS9DLEVBQXNELEdBQXRELEVBQTJELEVBQTNELEVBQStEO0FBQUV3RSxVQUFBQTtBQUFGLFNBQS9ELENBQXJDOztBQUNBLFlBQUlDLHNCQUFzQixDQUFDSyxNQUF2QixLQUFrQyxHQUF0QyxFQUEyQztBQUN6QyxpQkFBTyxrQ0FBYyxvQkFBZCxFQUFvQyxHQUFwQyxFQUF5QyxHQUF6QyxFQUE4QzdFLFFBQTlDLENBQVA7QUFDRDs7QUFBQTtBQUNELGVBQU8sTUFBTStELFlBQVksQ0FBQ2pFLE9BQUQsRUFBVUMsT0FBVixFQUFtQkMsUUFBbkIsQ0FBekI7QUFDRCxPQXZCRCxDQXVCRSxPQUFPc0QsS0FBUCxFQUFjO0FBQ2QsZUFBTyxrQ0FBY0EsS0FBSyxDQUFDTixPQUFOLElBQWlCTSxLQUEvQixFQUFzQ1UsU0FBdEMsRUFBaUQsR0FBakQsRUFBc0RoRSxRQUF0RCxDQUFQO0FBQ0Q7QUFDRixLQTNCRDtBQTRCRDs7QUE1TnlCIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIENsYXNzIGZvciBXYXp1aC1BUEkgZnVuY3Rpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG4vLyBSZXF1aXJlIHNvbWUgbGlicmFyaWVzXG5pbXBvcnQgeyBFcnJvclJlc3BvbnNlIH0gZnJvbSAnLi4vLi4vbGliL2Vycm9yLXJlc3BvbnNlJztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi8uLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgcmVhZCB9IGZyb20gJ3JlYWQtbGFzdC1saW5lcyc7XG5pbXBvcnQgeyBVcGRhdGVDb25maWd1cmF0aW9uRmlsZSB9IGZyb20gJy4uLy4uL2xpYi91cGRhdGUtY29uZmlndXJhdGlvbic7XG5pbXBvcnQgand0RGVjb2RlIGZyb20gJ2p3dC1kZWNvZGUnO1xuaW1wb3J0IHsgV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lELCBXQVpVSF9EQVRBX0xPR1NfUkFXX1BBVEgsIFBMVUdJTl9TRVRUSU5HUyB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgTWFuYWdlSG9zdHMgfSBmcm9tICcuLi8uLi9saWIvbWFuYWdlLWhvc3RzJztcbmltcG9ydCB7IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgUmVxdWVzdEhhbmRsZXJDb250ZXh0LCBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSB9IGZyb20gJ3NyYy9jb3JlL3NlcnZlcic7XG5pbXBvcnQgeyBnZXRDb29raWVWYWx1ZUJ5TmFtZSB9IGZyb20gJy4uLy4uL2xpYi9jb29raWUnO1xuaW1wb3J0IGZzIGZyb20gJ2ZzJztcbmltcG9ydCBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IHsgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMgfSBmcm9tICcuLi8uLi9saWIvZmlsZXN5c3RlbSc7XG5pbXBvcnQgZ2xvYiBmcm9tICdnbG9iJztcbmltcG9ydCB7IGdldEZpbGVFeHRlbnNpb25Gcm9tQnVmZmVyIH0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL3NlcnZpY2VzL2ZpbGUtZXh0ZW5zaW9uJztcblxuY29uc3QgdXBkYXRlQ29uZmlndXJhdGlvbkZpbGUgPSBuZXcgVXBkYXRlQ29uZmlndXJhdGlvbkZpbGUoKTtcblxuLy8gVE9ETzogdGhlc2UgY29udHJvbGxlcnMgaGF2ZSBubyBsb2dzLiBXZSBzaG91bGQgaW5jbHVkZSB0aGVtLlxuZXhwb3J0IGNsYXNzIFdhenVoVXRpbHNDdHJsIHtcbiAgLyoqXG4gICAqIENvbnN0cnVjdG9yXG4gICAqIEBwYXJhbSB7Kn0gc2VydmVyXG4gICAqL1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLm1hbmFnZUhvc3RzID0gbmV3IE1hbmFnZUhvc3RzKCk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgd2F6dWgueW1sIGZpbGUgcGFyc2VkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBDb25maWd1cmF0aW9uIEZpbGUgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgZ2V0Q29uZmlndXJhdGlvbkZpbGUoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBPcGVuU2VhcmNoRGFzaGJvYXJkc1JlcXVlc3QsIHJlc3BvbnNlOiBPcGVuU2VhcmNoRGFzaGJvYXJkc1Jlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb25maWdGaWxlID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuXG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7XG4gICAgICAgICAgc3RhdHVzQ29kZTogMjAwLFxuICAgICAgICAgIGVycm9yOiAwLFxuICAgICAgICAgIGRhdGE6IGNvbmZpZ0ZpbGUgfHwge31cbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDMwMTksIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSB3YXp1aC55bWwgZmlsZSBpbiByYXdcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IENvbmZpZ3VyYXRpb24gRmlsZSBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICB1cGRhdGVDb25maWd1cmF0aW9uRmlsZSA9IHRoaXMucm91dGVEZWNvcmF0b3JQcm90ZWN0ZWRBZG1pbmlzdHJhdG9yUm9sZVZhbGlkVG9rZW4oXG4gICAgYXN5bmMgKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogT3BlblNlYXJjaERhc2hib2FyZHNSZXF1ZXN0LCByZXNwb25zZTogT3BlblNlYXJjaERhc2hib2FyZHNSZXNwb25zZUZhY3RvcnkpID0+IHtcblxuICAgICAgbGV0IHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrOiBib29sZWFuID0gZmFsc2UsXG4gICAgICAgIHJlcXVpcmVzUmVsb2FkaW5nQnJvd3NlclRhYjogYm9vbGVhbiA9IGZhbHNlLFxuICAgICAgICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybTogYm9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAvLyBQbHVnaW4gc2V0dGluZ3MgY29uZmlndXJhYmxlcyBpbiB0aGUgY29uZmlndXJhdGlvbiBmaWxlLlxuICAgICAgY29uc3QgcGx1Z2luU2V0dGluZ3NDb25maWd1cmFibGVGaWxlID0gT2JqZWN0LmtleXMocmVxdWVzdC5ib2R5KVxuICAgICAgICAuZmlsdGVyKHBsdWdpblNldHRpbmdLZXkgPT4gUExVR0lOX1NFVFRJTkdTW3BsdWdpblNldHRpbmdLZXldLmlzQ29uZmlndXJhYmxlRnJvbUZpbGUpXG4gICAgICAgIC5yZWR1Y2UoKGFjY3VtLCBwbHVnaW5TZXR0aW5nS2V5OiBzdHJpbmcpID0+ICh7IC4uLmFjY3VtLCBbcGx1Z2luU2V0dGluZ0tleV06IHJlcXVlc3QuYm9keVtwbHVnaW5TZXR0aW5nS2V5XSB9KSwge30pO1xuXG4gICAgICBpZiAoT2JqZWN0LmtleXMocGx1Z2luU2V0dGluZ3NDb25maWd1cmFibGVGaWxlKS5sZW5ndGgpIHtcbiAgICAgICAgLy8gVXBkYXRlIHRoZSBjb25maWd1cmF0aW9uIGZpbGUuXG4gICAgICAgIGF3YWl0IHVwZGF0ZUNvbmZpZ3VyYXRpb25GaWxlLnVwZGF0ZUNvbmZpZ3VyYXRpb24ocGx1Z2luU2V0dGluZ3NDb25maWd1cmFibGVGaWxlKTtcblxuICAgICAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjayA9IE9iamVjdC5rZXlzKHBsdWdpblNldHRpbmdzQ29uZmlndXJhYmxlRmlsZSkuc29tZSgocGx1Z2luU2V0dGluZ0tleTogc3RyaW5nKSA9PiBCb29sZWFuKFBMVUdJTl9TRVRUSU5HU1twbHVnaW5TZXR0aW5nS2V5XS5yZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjaykpIHx8IHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrO1xuICAgICAgICByZXF1aXJlc1JlbG9hZGluZ0Jyb3dzZXJUYWIgPSBPYmplY3Qua2V5cyhwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYWJsZUZpbGUpLnNvbWUoKHBsdWdpblNldHRpbmdLZXk6IHN0cmluZykgPT4gQm9vbGVhbihQTFVHSU5fU0VUVElOR1NbcGx1Z2luU2V0dGluZ0tleV0ucmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiKSkgfHwgcmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiO1xuICAgICAgICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybSA9IE9iamVjdC5rZXlzKHBsdWdpblNldHRpbmdzQ29uZmlndXJhYmxlRmlsZSkuc29tZSgocGx1Z2luU2V0dGluZ0tleTogc3RyaW5nKSA9PiBCb29sZWFuKFBMVUdJTl9TRVRUSU5HU1twbHVnaW5TZXR0aW5nS2V5XS5yZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybSkpIHx8IHJlcXVpcmVzUmVzdGFydGluZ1BsdWdpblBsYXRmb3JtO1xuICAgICAgfTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIGRhdGE6IHsgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2ssIHJlcXVpcmVzUmVsb2FkaW5nQnJvd3NlclRhYiwgcmVxdWlyZXNSZXN0YXJ0aW5nUGx1Z2luUGxhdGZvcm0sIHVwZGF0ZWRDb25maWd1cmF0aW9uOiBwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYWJsZUZpbGUgfVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9LFxuICAgIDMwMjFcbiAgKVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIFdhenVoIGFwcCBsb2dzXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7QXJyYXk8U3RyaW5nPn0gYXBwIGxvZ3Mgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0QXBwTG9ncyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgcmVzcG9uc2U6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGxhc3RMb2dzID0gYXdhaXQgcmVhZChcbiAgICAgICAgV0FaVUhfREFUQV9MT0dTX1JBV19QQVRILFxuICAgICAgICA1MFxuICAgICAgKTtcbiAgICAgIGNvbnN0IHNwbGl0ZXJMb2cgPSBsYXN0TG9ncy5zcGxpdCgnXFxuJyk7XG4gICAgICByZXR1cm4gc3BsaXRlckxvZyAmJiBBcnJheS5pc0FycmF5KHNwbGl0ZXJMb2cpXG4gICAgICAgID8gcmVzcG9uc2Uub2soe1xuICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgIGVycm9yOiAwLFxuICAgICAgICAgICAgbGFzdExvZ3M6IHNwbGl0ZXJMb2cuZmlsdGVyKFxuICAgICAgICAgICAgICBpdGVtID0+IHR5cGVvZiBpdGVtID09PSAnc3RyaW5nJyAmJiBpdGVtLmxlbmd0aFxuICAgICAgICAgICAgKVxuICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgOiByZXNwb25zZS5vayh7IGVycm9yOiAwLCBsYXN0TG9nczogW10gfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDMwMzYsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBVcGxvYWQgYSBmaWxlXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBDb25maWd1cmF0aW9uIEZpbGUgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgdXBsb2FkRmlsZSA9IHRoaXMucm91dGVEZWNvcmF0b3JQcm90ZWN0ZWRBZG1pbmlzdHJhdG9yUm9sZVZhbGlkVG9rZW4oXG4gICAgYXN5bmMgKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkgPT4ge1xuICAgICAgY29uc3QgeyBrZXkgfSA9IHJlcXVlc3QucGFyYW1zO1xuICAgICAgY29uc3QgeyBmaWxlOiBidWZmZXJGaWxlIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICBjb25zdCBwbHVnaW5TZXR0aW5nID0gUExVR0lOX1NFVFRJTkdTW2tleV07XG5cbiAgICAgIC8vIENoZWNrIGZpbGUgZXh0ZW5zaW9uXG4gICAgICBjb25zdCBmaWxlRXh0ZW5zaW9uID0gZ2V0RmlsZUV4dGVuc2lvbkZyb21CdWZmZXIoYnVmZmVyRmlsZSk7XG5cbiAgICAgIC8vIENoZWNrIGlmIHRoZSBleHRlbnNpb24gaXMgdmFsaWQgZm9yIHRoZSBzZXR0aW5nLlxuICAgICAgaWYgKCFwbHVnaW5TZXR0aW5nLm9wdGlvbnMuZmlsZS5leHRlbnNpb25zLmluY2x1ZGVzKGAuJHtmaWxlRXh0ZW5zaW9ufWApKSB7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5iYWRSZXF1ZXN0KHtcbiAgICAgICAgICBib2R5OiBgRmlsZSBleHRlbnNpb24gaXMgbm90IHZhbGlkIGZvciBzZXR0aW5nIFske2tleX1dIHNldHRpbmcuIEFsbG93ZWQgZmlsZSBleHRlbnNpb25zOiAke3BsdWdpblNldHRpbmcub3B0aW9ucy5maWxlLmV4dGVuc2lvbnMuam9pbignLCAnKX1gXG4gICAgICAgIH0pO1xuICAgICAgfTtcblxuICAgICAgY29uc3QgZmlsZU5hbWVQYXRoID0gYCR7a2V5fS4ke2ZpbGVFeHRlbnNpb259YDtcblxuICAgICAgLy8gQ3JlYXRlIHRhcmdldCBkaXJlY3RvcnlcbiAgICAgIGNvbnN0IHRhcmdldERpcmVjdG9yeSA9IHBhdGguam9pbihfX2Rpcm5hbWUsICcuLi8uLi8uLicsIHBsdWdpblNldHRpbmcub3B0aW9ucy5maWxlLnN0b3JlLnJlbGF0aXZlUGF0aEZpbGVTeXN0ZW0pO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHModGFyZ2V0RGlyZWN0b3J5KTtcbiAgICAgIC8vIEdldCB0aGUgZmlsZXMgcmVsYXRlZCB0byB0aGUgc2V0dGluZyBhbmQgcmVtb3ZlIHRoZW1cbiAgICAgIGNvbnN0IGZpbGVzID0gZ2xvYi5zeW5jKHBhdGguam9pbih0YXJnZXREaXJlY3RvcnksIGAke2tleX0uKmApKTtcbiAgICAgIGZpbGVzLmZvckVhY2goZnMudW5saW5rU3luYyk7XG5cbiAgICAgIC8vIFN0b3JlIHRoZSBmaWxlIGluIHRoZSB0YXJnZXQgZGlyZWN0b3J5LlxuICAgICAgZnMud3JpdGVGaWxlU3luYyhwYXRoLmpvaW4odGFyZ2V0RGlyZWN0b3J5LCBmaWxlTmFtZVBhdGgpLCBidWZmZXJGaWxlKTtcblxuICAgICAgLy8gVXBkYXRlIHRoZSBzZXR0aW5nIGluIHRoZSBjb25maWd1cmF0aW9uIGNhY2hlXG4gICAgICBjb25zdCBwbHVnaW5TZXR0aW5nVmFsdWUgPSBwbHVnaW5TZXR0aW5nLm9wdGlvbnMuZmlsZS5zdG9yZS5yZXNvbHZlU3RhdGljVVJMKGZpbGVOYW1lUGF0aCk7XG4gICAgICBhd2FpdCB1cGRhdGVDb25maWd1cmF0aW9uRmlsZS51cGRhdGVDb25maWd1cmF0aW9uKHsgW2tleV06IHBsdWdpblNldHRpbmdWYWx1ZSB9KTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIGRhdGE6IHtcbiAgICAgICAgICAgIHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrOiBCb29sZWFuKHBsdWdpblNldHRpbmcucmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2spLFxuICAgICAgICAgICAgcmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiOiBCb29sZWFuKHBsdWdpblNldHRpbmcucmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiKSxcbiAgICAgICAgICAgIHJlcXVpcmVzUmVzdGFydGluZ1BsdWdpblBsYXRmb3JtOiBCb29sZWFuKHBsdWdpblNldHRpbmcucmVxdWlyZXNSZXN0YXJ0aW5nUGx1Z2luUGxhdGZvcm0pLFxuICAgICAgICAgICAgdXBkYXRlZENvbmZpZ3VyYXRpb246IHtcbiAgICAgICAgICAgICAgW2tleV06IHBsdWdpblNldHRpbmdWYWx1ZVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgICAzMDIyXG4gIClcblxuICAvKipcbiAgICogRGVsZXRlIGEgZmlsZVxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gQ29uZmlndXJhdGlvbiBGaWxlIG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGRlbGV0ZUZpbGUgPSB0aGlzLnJvdXRlRGVjb3JhdG9yUHJvdGVjdGVkQWRtaW5pc3RyYXRvclJvbGVWYWxpZFRva2VuKFxuICAgIGFzeW5jIChjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpID0+IHtcbiAgICAgIGNvbnN0IHsga2V5IH0gPSByZXF1ZXN0LnBhcmFtcztcbiAgICAgIGNvbnN0IHBsdWdpblNldHRpbmcgPSBQTFVHSU5fU0VUVElOR1Nba2V5XTtcblxuICAgICAgLy8gR2V0IHRoZSBmaWxlcyByZWxhdGVkIHRvIHRoZSBzZXR0aW5nIGFuZCByZW1vdmUgdGhlbVxuICAgICAgY29uc3QgdGFyZ2V0RGlyZWN0b3J5ID0gcGF0aC5qb2luKF9fZGlybmFtZSwgJy4uLy4uLy4uJywgcGx1Z2luU2V0dGluZy5vcHRpb25zLmZpbGUuc3RvcmUucmVsYXRpdmVQYXRoRmlsZVN5c3RlbSk7XG4gICAgICBjb25zdCBmaWxlcyA9IGdsb2Iuc3luYyhwYXRoLmpvaW4odGFyZ2V0RGlyZWN0b3J5LCBgJHtrZXl9LipgKSk7XG4gICAgICBmaWxlcy5mb3JFYWNoKGZzLnVubGlua1N5bmMpO1xuXG4gICAgICAvLyBVcGRhdGUgdGhlIHNldHRpbmcgaW4gdGhlIGNvbmZpZ3VyYXRpb24gY2FjaGVcbiAgICAgIGNvbnN0IHBsdWdpblNldHRpbmdWYWx1ZSA9IHBsdWdpblNldHRpbmcuZGVmYXVsdFZhbHVlO1xuICAgICAgYXdhaXQgdXBkYXRlQ29uZmlndXJhdGlvbkZpbGUudXBkYXRlQ29uZmlndXJhdGlvbih7IFtrZXldOiBwbHVnaW5TZXR0aW5nVmFsdWUgfSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBtZXNzYWdlOiAnQWxsIGZpbGVzIHdlcmUgcmVtb3ZlZCBhbmQgdGhlIGNvbmZpZ3VyYXRpb24gZmlsZSB3YXMgdXBkYXRlZC4nLFxuICAgICAgICAgIGRhdGE6IHtcbiAgICAgICAgICAgIHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrOiBCb29sZWFuKHBsdWdpblNldHRpbmcucmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2spLFxuICAgICAgICAgICAgcmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiOiBCb29sZWFuKHBsdWdpblNldHRpbmcucmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiKSxcbiAgICAgICAgICAgIHJlcXVpcmVzUmVzdGFydGluZ1BsdWdpblBsYXRmb3JtOiBCb29sZWFuKHBsdWdpblNldHRpbmcucmVxdWlyZXNSZXN0YXJ0aW5nUGx1Z2luUGxhdGZvcm0pLFxuICAgICAgICAgICAgdXBkYXRlZENvbmZpZ3VyYXRpb246IHtcbiAgICAgICAgICAgICAgW2tleV06IHBsdWdpblNldHRpbmdWYWx1ZVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSxcbiAgICAzMDIzXG4gIClcblxuICBwcml2YXRlIHJvdXRlRGVjb3JhdG9yUHJvdGVjdGVkQWRtaW5pc3RyYXRvclJvbGVWYWxpZFRva2VuKHJvdXRlSGFuZGxlciwgZXJyb3JDb2RlOiBudW1iZXIpIHtcbiAgICByZXR1cm4gYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICAvLyBDaGVjayBpZiB1c2VyIGhhcyBhZG1pbmlzdHJhdG9yIHJvbGUgaW4gdG9rZW5cbiAgICAgICAgY29uc3QgdG9rZW4gPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCAnd3otdG9rZW4nKTtcbiAgICAgICAgaWYgKCF0b2tlbikge1xuICAgICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyB0b2tlbiBwcm92aWRlZCcsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICAgIH07XG4gICAgICAgIGNvbnN0IGRlY29kZWRUb2tlbiA9IGp3dERlY29kZSh0b2tlbik7XG4gICAgICAgIGlmICghZGVjb2RlZFRva2VuKSB7XG4gICAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIHBlcm1pc3Npb25zIGluIHRva2VuJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKCFkZWNvZGVkVG9rZW4ucmJhY19yb2xlcyB8fCAhZGVjb2RlZFRva2VuLnJiYWNfcm9sZXMuaW5jbHVkZXMoV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lEKSkge1xuICAgICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBhZG1pbmlzdHJhdG9yIHJvbGUnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgICB9O1xuICAgICAgICAvLyBDaGVjayB0aGUgcHJvdmlkZWQgdG9rZW4gaXMgdmFsaWRcbiAgICAgICAgY29uc3QgYXBpSG9zdElEID0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LWFwaScpO1xuICAgICAgICBpZiAoIWFwaUhvc3RJRCkge1xuICAgICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBBUEkgaWQgcHJvdmlkZWQnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgICB9O1xuICAgICAgICBjb25zdCByZXNwb25zZVRva2VuSXNXb3JraW5nID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdCgnR0VUJywgJy8nLCB7fSwgeyBhcGlIb3N0SUQgfSk7XG4gICAgICAgIGlmIChyZXNwb25zZVRva2VuSXNXb3JraW5nLnN0YXR1cyAhPT0gMjAwKSB7XG4gICAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ1Rva2VuIGlzIG5vdCB2YWxpZCcsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiBhd2FpdCByb3V0ZUhhbmRsZXIoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCBlcnJvckNvZGUsIDUwMCwgcmVzcG9uc2UpO1xuICAgICAgfVxuICAgIH1cbiAgfVxufVxuIl19