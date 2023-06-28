"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhUtilsRoutes = WazuhUtilsRoutes;

var _controllers = require("../../controllers");

var _configSchema = require("@osd/config-schema");

var _constants = require("../../../common/constants");

/*
 * Wazuh app - Module for Wazuh utils routes
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
function WazuhUtilsRoutes(router) {
  const ctrl = new _controllers.WazuhUtilsCtrl(); // Returns the wazuh.yml file parsed

  router.get({
    path: '/utils/configuration',
    validate: false
  }, async (context, request, response) => ctrl.getConfigurationFile(context, request, response)); // Returns the wazuh.yml file in raw

  router.put({
    path: '/utils/configuration',
    validate: {
      body: _configSchema.schema.object(Object.entries(_constants.PLUGIN_SETTINGS).filter(([, {
        isConfigurableFromFile
      }]) => isConfigurableFromFile).reduce((accum, [pluginSettingKey, pluginSettingConfiguration]) => ({ ...accum,
        [pluginSettingKey]: _configSchema.schema.maybe(pluginSettingConfiguration.validateBackend ? pluginSettingConfiguration.validateBackend(_configSchema.schema) : _configSchema.schema.any())
      }), {}))
    }
  }, async (context, request, response) => ctrl.updateConfigurationFile(context, request, response));
  const pluginSettingsTypeFilepicker = Object.entries(_constants.PLUGIN_SETTINGS).filter(([_, {
    type,
    isConfigurableFromFile
  }]) => type === _constants.EpluginSettingType.filepicker && isConfigurableFromFile);

  const schemaPluginSettingsTypeFilepicker = _configSchema.schema.oneOf(pluginSettingsTypeFilepicker.map(([pluginSettingKey]) => _configSchema.schema.literal(pluginSettingKey))); // Upload an asset


  router.put({
    path: '/utils/configuration/files/{key}',
    validate: {
      params: _configSchema.schema.object({
        // key parameter should be a plugin setting of `filepicker` type
        key: schemaPluginSettingsTypeFilepicker
      }),
      body: _configSchema.schema.object({
        // file: buffer
        file: _configSchema.schema.buffer()
      })
    },
    options: {
      body: {
        maxBytes: _constants.CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
      }
    }
  }, async (context, request, response) => ctrl.uploadFile(context, request, response)); // Remove an asset

  router.delete({
    path: '/utils/configuration/files/{key}',
    validate: {
      params: _configSchema.schema.object({
        // key parameter should be a plugin setting of `filepicker` type
        key: schemaPluginSettingsTypeFilepicker
      })
    }
  }, async (context, request, response) => ctrl.deleteFile(context, request, response)); // Returns Wazuh app logs

  router.get({
    path: '/utils/logs',
    validate: false
  }, async (context, request, response) => ctrl.getAppLogs(context, request, response));
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLXV0aWxzLnRzIl0sIm5hbWVzIjpbIldhenVoVXRpbHNSb3V0ZXMiLCJyb3V0ZXIiLCJjdHJsIiwiV2F6dWhVdGlsc0N0cmwiLCJnZXQiLCJwYXRoIiwidmFsaWRhdGUiLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiZ2V0Q29uZmlndXJhdGlvbkZpbGUiLCJwdXQiLCJib2R5Iiwic2NoZW1hIiwib2JqZWN0IiwiT2JqZWN0IiwiZW50cmllcyIsIlBMVUdJTl9TRVRUSU5HUyIsImZpbHRlciIsImlzQ29uZmlndXJhYmxlRnJvbUZpbGUiLCJyZWR1Y2UiLCJhY2N1bSIsInBsdWdpblNldHRpbmdLZXkiLCJwbHVnaW5TZXR0aW5nQ29uZmlndXJhdGlvbiIsIm1heWJlIiwidmFsaWRhdGVCYWNrZW5kIiwiYW55IiwidXBkYXRlQ29uZmlndXJhdGlvbkZpbGUiLCJwbHVnaW5TZXR0aW5nc1R5cGVGaWxlcGlja2VyIiwiXyIsInR5cGUiLCJFcGx1Z2luU2V0dGluZ1R5cGUiLCJmaWxlcGlja2VyIiwic2NoZW1hUGx1Z2luU2V0dGluZ3NUeXBlRmlsZXBpY2tlciIsIm9uZU9mIiwibWFwIiwibGl0ZXJhbCIsInBhcmFtcyIsImtleSIsImZpbGUiLCJidWZmZXIiLCJvcHRpb25zIiwibWF4Qnl0ZXMiLCJDVVNUT01JWkFUSU9OX0VORFBPSU5UX1BBWUxPQURfVVBMT0FEX0NVU1RPTV9GSUxFX01BWElNVU1fQllURVMiLCJ1cGxvYWRGaWxlIiwiZGVsZXRlIiwiZGVsZXRlRmlsZSIsImdldEFwcExvZ3MiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFFQTs7QUFDQTs7QUFkQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBTU8sU0FBU0EsZ0JBQVQsQ0FBMEJDLE1BQTFCLEVBQTJDO0FBQ2hELFFBQU1DLElBQUksR0FBRyxJQUFJQywyQkFBSixFQUFiLENBRGdELENBR2hEOztBQUNBRixFQUFBQSxNQUFNLENBQUNHLEdBQVAsQ0FDRTtBQUNFQyxJQUFBQSxJQUFJLEVBQUUsc0JBRFI7QUFFRUMsSUFBQUEsUUFBUSxFQUFFO0FBRlosR0FERixFQUtFLE9BQU9DLE9BQVAsRUFBZ0JDLE9BQWhCLEVBQXlCQyxRQUF6QixLQUFzQ1AsSUFBSSxDQUFDUSxvQkFBTCxDQUEwQkgsT0FBMUIsRUFBbUNDLE9BQW5DLEVBQTRDQyxRQUE1QyxDQUx4QyxFQUpnRCxDQVloRDs7QUFDQVIsRUFBQUEsTUFBTSxDQUFDVSxHQUFQLENBQ0U7QUFDRU4sSUFBQUEsSUFBSSxFQUFFLHNCQURSO0FBRUVDLElBQUFBLFFBQVEsRUFBRTtBQUNSTSxNQUFBQSxJQUFJLEVBQUVDLHFCQUFPQyxNQUFQLENBQ0pDLE1BQU0sQ0FBQ0MsT0FBUCxDQUFlQywwQkFBZixFQUNHQyxNQURILENBQ1UsQ0FBQyxHQUFHO0FBQUVDLFFBQUFBO0FBQUYsT0FBSCxDQUFELEtBQW9DQSxzQkFEOUMsRUFFR0MsTUFGSCxDQUdJLENBQUNDLEtBQUQsRUFBUSxDQUFDQyxnQkFBRCxFQUFtQkMsMEJBQW5CLENBQVIsTUFBNEQsRUFDMUQsR0FBR0YsS0FEdUQ7QUFFMUQsU0FBQ0MsZ0JBQUQsR0FBb0JULHFCQUFPVyxLQUFQLENBQ2xCRCwwQkFBMEIsQ0FBQ0UsZUFBM0IsR0FDSUYsMEJBQTBCLENBQUNFLGVBQTNCLENBQTJDWixvQkFBM0MsQ0FESixHQUVJQSxxQkFBT2EsR0FBUCxFQUhjO0FBRnNDLE9BQTVELENBSEosRUFXSSxFQVhKLENBREk7QUFERTtBQUZaLEdBREYsRUFxQkUsT0FBT25CLE9BQVAsRUFBZ0JDLE9BQWhCLEVBQXlCQyxRQUF6QixLQUFzQ1AsSUFBSSxDQUFDeUIsdUJBQUwsQ0FBNkJwQixPQUE3QixFQUFzQ0MsT0FBdEMsRUFBK0NDLFFBQS9DLENBckJ4QztBQXdCQSxRQUFNbUIsNEJBQTRCLEdBQUdiLE1BQU0sQ0FBQ0MsT0FBUCxDQUFlQywwQkFBZixFQUNsQ0MsTUFEa0MsQ0FDM0IsQ0FBQyxDQUFDVyxDQUFELEVBQUk7QUFBRUMsSUFBQUEsSUFBRjtBQUFRWCxJQUFBQTtBQUFSLEdBQUosQ0FBRCxLQUEyQ1csSUFBSSxLQUFLQyw4QkFBbUJDLFVBQTVCLElBQTBDYixzQkFEMUQsQ0FBckM7O0FBR0EsUUFBTWMsa0NBQWtDLEdBQUdwQixxQkFBT3FCLEtBQVAsQ0FBYU4sNEJBQTRCLENBQUNPLEdBQTdCLENBQWlDLENBQUMsQ0FBQ2IsZ0JBQUQsQ0FBRCxLQUF3QlQscUJBQU91QixPQUFQLENBQWVkLGdCQUFmLENBQXpELENBQWIsQ0FBM0MsQ0F4Q2dELENBMENoRDs7O0FBQ0FyQixFQUFBQSxNQUFNLENBQUNVLEdBQVAsQ0FDRTtBQUNFTixJQUFBQSxJQUFJLEVBQUUsa0NBRFI7QUFFRUMsSUFBQUEsUUFBUSxFQUFFO0FBQ1IrQixNQUFBQSxNQUFNLEVBQUV4QixxQkFBT0MsTUFBUCxDQUFjO0FBQ3BCO0FBQ0F3QixRQUFBQSxHQUFHLEVBQUVMO0FBRmUsT0FBZCxDQURBO0FBS1JyQixNQUFBQSxJQUFJLEVBQUVDLHFCQUFPQyxNQUFQLENBQWM7QUFDbEI7QUFDQXlCLFFBQUFBLElBQUksRUFBRTFCLHFCQUFPMkIsTUFBUDtBQUZZLE9BQWQ7QUFMRSxLQUZaO0FBWUVDLElBQUFBLE9BQU8sRUFBRTtBQUNQN0IsTUFBQUEsSUFBSSxFQUFFO0FBQ0o4QixRQUFBQSxRQUFRLEVBQUVDO0FBRE47QUFEQztBQVpYLEdBREYsRUFtQkUsT0FBT3BDLE9BQVAsRUFBZ0JDLE9BQWhCLEVBQXlCQyxRQUF6QixLQUFzQ1AsSUFBSSxDQUFDMEMsVUFBTCxDQUFnQnJDLE9BQWhCLEVBQXlCQyxPQUF6QixFQUFrQ0MsUUFBbEMsQ0FuQnhDLEVBM0NnRCxDQWlFaEQ7O0FBQ0FSLEVBQUFBLE1BQU0sQ0FBQzRDLE1BQVAsQ0FDRTtBQUNFeEMsSUFBQUEsSUFBSSxFQUFFLGtDQURSO0FBRUVDLElBQUFBLFFBQVEsRUFBRTtBQUNSK0IsTUFBQUEsTUFBTSxFQUFFeEIscUJBQU9DLE1BQVAsQ0FBYztBQUNwQjtBQUNBd0IsUUFBQUEsR0FBRyxFQUFFTDtBQUZlLE9BQWQ7QUFEQTtBQUZaLEdBREYsRUFVRSxPQUFPMUIsT0FBUCxFQUFnQkMsT0FBaEIsRUFBeUJDLFFBQXpCLEtBQXNDUCxJQUFJLENBQUM0QyxVQUFMLENBQWdCdkMsT0FBaEIsRUFBeUJDLE9BQXpCLEVBQWtDQyxRQUFsQyxDQVZ4QyxFQWxFZ0QsQ0ErRWhEOztBQUNBUixFQUFBQSxNQUFNLENBQUNHLEdBQVAsQ0FDRTtBQUNFQyxJQUFBQSxJQUFJLEVBQUUsYUFEUjtBQUVFQyxJQUFBQSxRQUFRLEVBQUU7QUFGWixHQURGLEVBS0UsT0FBT0MsT0FBUCxFQUFnQkMsT0FBaEIsRUFBeUJDLFFBQXpCLEtBQXNDUCxJQUFJLENBQUM2QyxVQUFMLENBQWdCeEMsT0FBaEIsRUFBeUJDLE9BQXpCLEVBQWtDQyxRQUFsQyxDQUx4QztBQU9EIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgV2F6dWggdXRpbHMgcm91dGVzXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHsgV2F6dWhVdGlsc0N0cmwgfSBmcm9tICcuLi8uLi9jb250cm9sbGVycyc7XG5pbXBvcnQgeyBJUm91dGVyIH0gZnJvbSAnb3BlbnNlYXJjaF9kYXNoYm9hcmRzL3NlcnZlcic7XG5pbXBvcnQgeyBzY2hlbWEgfSBmcm9tICdAb3NkL2NvbmZpZy1zY2hlbWEnO1xuaW1wb3J0IHsgQ1VTVE9NSVpBVElPTl9FTkRQT0lOVF9QQVlMT0FEX1VQTE9BRF9DVVNUT01fRklMRV9NQVhJTVVNX0JZVEVTLCBFcGx1Z2luU2V0dGluZ1R5cGUsIFBMVUdJTl9TRVRUSU5HUyB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuXG5leHBvcnQgZnVuY3Rpb24gV2F6dWhVdGlsc1JvdXRlcyhyb3V0ZXI6IElSb3V0ZXIpIHtcbiAgY29uc3QgY3RybCA9IG5ldyBXYXp1aFV0aWxzQ3RybCgpO1xuXG4gIC8vIFJldHVybnMgdGhlIHdhenVoLnltbCBmaWxlIHBhcnNlZFxuICByb3V0ZXIuZ2V0KFxuICAgIHtcbiAgICAgIHBhdGg6ICcvdXRpbHMvY29uZmlndXJhdGlvbicsXG4gICAgICB2YWxpZGF0ZTogZmFsc2VcbiAgICB9LFxuICAgIGFzeW5jIChjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSkgPT4gY3RybC5nZXRDb25maWd1cmF0aW9uRmlsZShjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZXR1cm5zIHRoZSB3YXp1aC55bWwgZmlsZSBpbiByYXdcbiAgcm91dGVyLnB1dChcbiAgICB7XG4gICAgICBwYXRoOiAnL3V0aWxzL2NvbmZpZ3VyYXRpb24nLFxuICAgICAgdmFsaWRhdGU6IHtcbiAgICAgICAgYm9keTogc2NoZW1hLm9iamVjdChcbiAgICAgICAgICBPYmplY3QuZW50cmllcyhQTFVHSU5fU0VUVElOR1MpXG4gICAgICAgICAgICAuZmlsdGVyKChbLCB7IGlzQ29uZmlndXJhYmxlRnJvbUZpbGUgfV0pID0+IGlzQ29uZmlndXJhYmxlRnJvbUZpbGUpXG4gICAgICAgICAgICAucmVkdWNlKFxuICAgICAgICAgICAgICAoYWNjdW0sIFtwbHVnaW5TZXR0aW5nS2V5LCBwbHVnaW5TZXR0aW5nQ29uZmlndXJhdGlvbl0pID0+ICh7XG4gICAgICAgICAgICAgICAgLi4uYWNjdW0sXG4gICAgICAgICAgICAgICAgW3BsdWdpblNldHRpbmdLZXldOiBzY2hlbWEubWF5YmUoXG4gICAgICAgICAgICAgICAgICBwbHVnaW5TZXR0aW5nQ29uZmlndXJhdGlvbi52YWxpZGF0ZUJhY2tlbmRcbiAgICAgICAgICAgICAgICAgICAgPyBwbHVnaW5TZXR0aW5nQ29uZmlndXJhdGlvbi52YWxpZGF0ZUJhY2tlbmQoc2NoZW1hKVxuICAgICAgICAgICAgICAgICAgICA6IHNjaGVtYS5hbnkoKVxuICAgICAgICAgICAgICAgICksXG4gICAgICAgICAgICAgIH0pLFxuICAgICAgICAgICAgICB7fVxuICAgICAgICAgICAgKVxuICAgICAgICApXG4gICAgICB9XG4gICAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwudXBkYXRlQ29uZmlndXJhdGlvbkZpbGUoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG5cbiAgY29uc3QgcGx1Z2luU2V0dGluZ3NUeXBlRmlsZXBpY2tlciA9IE9iamVjdC5lbnRyaWVzKFBMVUdJTl9TRVRUSU5HUylcbiAgICAuZmlsdGVyKChbXywgeyB0eXBlLCBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlIH1dKSA9PiB0eXBlID09PSBFcGx1Z2luU2V0dGluZ1R5cGUuZmlsZXBpY2tlciAmJiBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlKTtcblxuICBjb25zdCBzY2hlbWFQbHVnaW5TZXR0aW5nc1R5cGVGaWxlcGlja2VyID0gc2NoZW1hLm9uZU9mKHBsdWdpblNldHRpbmdzVHlwZUZpbGVwaWNrZXIubWFwKChbcGx1Z2luU2V0dGluZ0tleV0pID0+IHNjaGVtYS5saXRlcmFsKHBsdWdpblNldHRpbmdLZXkpKSk7XG5cbiAgLy8gVXBsb2FkIGFuIGFzc2V0XG4gIHJvdXRlci5wdXQoXG4gICAge1xuICAgICAgcGF0aDogJy91dGlscy9jb25maWd1cmF0aW9uL2ZpbGVzL3trZXl9JyxcbiAgICAgIHZhbGlkYXRlOiB7XG4gICAgICAgIHBhcmFtczogc2NoZW1hLm9iamVjdCh7XG4gICAgICAgICAgLy8ga2V5IHBhcmFtZXRlciBzaG91bGQgYmUgYSBwbHVnaW4gc2V0dGluZyBvZiBgZmlsZXBpY2tlcmAgdHlwZVxuICAgICAgICAgIGtleTogc2NoZW1hUGx1Z2luU2V0dGluZ3NUeXBlRmlsZXBpY2tlclxuICAgICAgICB9KSxcbiAgICAgICAgYm9keTogc2NoZW1hLm9iamVjdCh7XG4gICAgICAgICAgLy8gZmlsZTogYnVmZmVyXG4gICAgICAgICAgZmlsZTogc2NoZW1hLmJ1ZmZlcigpLFxuICAgICAgICB9KVxuICAgICAgfSxcbiAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIG1heEJ5dGVzOiBDVVNUT01JWkFUSU9OX0VORFBPSU5UX1BBWUxPQURfVVBMT0FEX0NVU1RPTV9GSUxFX01BWElNVU1fQllURVMsXG4gICAgICAgIH0sXG4gICAgICB9XG4gICAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwudXBsb2FkRmlsZShjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZW1vdmUgYW4gYXNzZXRcbiAgcm91dGVyLmRlbGV0ZShcbiAgICB7XG4gICAgICBwYXRoOiAnL3V0aWxzL2NvbmZpZ3VyYXRpb24vZmlsZXMve2tleX0nLFxuICAgICAgdmFsaWRhdGU6IHtcbiAgICAgICAgcGFyYW1zOiBzY2hlbWEub2JqZWN0KHtcbiAgICAgICAgICAvLyBrZXkgcGFyYW1ldGVyIHNob3VsZCBiZSBhIHBsdWdpbiBzZXR0aW5nIG9mIGBmaWxlcGlja2VyYCB0eXBlXG4gICAgICAgICAga2V5OiBzY2hlbWFQbHVnaW5TZXR0aW5nc1R5cGVGaWxlcGlja2VyXG4gICAgICAgIH0pXG4gICAgICB9XG4gICAgfSxcbiAgICBhc3luYyAoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpID0+IGN0cmwuZGVsZXRlRmlsZShjb250ZXh0LCByZXF1ZXN0LCByZXNwb25zZSlcbiAgKTtcblxuICAvLyBSZXR1cm5zIFdhenVoIGFwcCBsb2dzXG4gIHJvdXRlci5nZXQoXG4gICAge1xuICAgICAgcGF0aDogJy91dGlscy9sb2dzJyxcbiAgICAgIHZhbGlkYXRlOiBmYWxzZVxuICAgIH0sXG4gICAgYXN5bmMgKGNvbnRleHQsIHJlcXVlc3QsIHJlc3BvbnNlKSA9PiBjdHJsLmdldEFwcExvZ3MoY29udGV4dCwgcmVxdWVzdCwgcmVzcG9uc2UpXG4gICk7XG59XG4iXX0=