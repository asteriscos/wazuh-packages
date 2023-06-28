"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.initialWazuhConfig = exports.hostsConfiguration = exports.header = void 0;
exports.printSection = printSection;
exports.printSetting = printSetting;
exports.printSettingCategory = printSettingCategory;
exports.printSettingValue = printSettingValue;
exports.splitDescription = splitDescription;

var _constants = require("../../common/constants");

var _settings = require("../../common/services/settings");

var _web_documentation = require("../../common/services/web_documentation");

/*
 * Wazuh app - App configuration file
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const header = `---
#
# ${_constants.PLUGIN_APP_NAME} - App configuration file
# Copyright (C) 2015-2022 Wazuh, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Find more information about this on the LICENSE file.
#
${printSection('Wazuh app configuration file', {
  prefix: '# ',
  fill: '='
})}
#
# Please check the documentation for more information about configuration options:
# ${(0, _web_documentation.webDocumentationLink)('user-manual/wazuh-dashboard/config-file.html')}
#
# Also, you can check our repository:
# https://github.com/wazuh/wazuh-kibana-app`;
exports.header = header;
const pluginSettingsConfigurationFile = (0, _settings.getSettingsDefaultList)().filter(({
  isConfigurableFromFile
}) => isConfigurableFromFile);
const pluginSettingsConfigurationFileGroupByCategory = (0, _settings.groupSettingsByCategory)(pluginSettingsConfigurationFile);
const pluginSettingsConfiguration = pluginSettingsConfigurationFileGroupByCategory.map(({
  category: categoryID,
  settings
}) => {
  const category = printSettingCategory(_constants.PLUGIN_SETTINGS_CATEGORIES[categoryID]);
  const pluginSettingsOfCategory = settings.map(setting => printSetting(setting)).join('\n#\n');
  /*
  #------------------- {category name} --------------
  #
  #  {category description}
  #
  # {setting description}
  # settingKey: settingDefaultValue
  #
  # {setting description}
  # settingKey: settingDefaultValue
  # ...
  */

  return [category, pluginSettingsOfCategory].join('\n#\n');
}).join('\n#\n');

function printSettingValue(value) {
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }

  ;

  if (typeof value === 'string' && value.length === 0) {
    return `''`;
  }

  ;
  return value;
}

;

function printSetting(setting) {
  /*
  # {setting description}
  # {settingKey}: {settingDefaultValue}
  */
  return [splitDescription((0, _settings.getPluginSettingDescription)(setting)), `# ${setting.key}: ${printSettingValue(setting.defaultValue)}`].join('\n');
}

function printSettingCategory({
  title,
  description
}) {
  /*
  #------------------------------- {category title} -------------------------------
  # {category description}
  #
  */
  return [printSection(title, {
    prefix: '# ',
    fill: '-'
  }), ...(description ? [splitDescription(description)] : [''])].join('\n#\n');
}

;

function printSection(text, options) {
  var _options$maxLength, _options$prefix, _options$suffix, _options$spaceAround, _options$fill;

  const maxLength = (_options$maxLength = options === null || options === void 0 ? void 0 : options.maxLength) !== null && _options$maxLength !== void 0 ? _options$maxLength : 80;
  const prefix = (_options$prefix = options === null || options === void 0 ? void 0 : options.prefix) !== null && _options$prefix !== void 0 ? _options$prefix : '';
  const sufix = (_options$suffix = options === null || options === void 0 ? void 0 : options.suffix) !== null && _options$suffix !== void 0 ? _options$suffix : '';
  const spaceAround = (_options$spaceAround = options === null || options === void 0 ? void 0 : options.spaceAround) !== null && _options$spaceAround !== void 0 ? _options$spaceAround : 1;
  const fill = (_options$fill = options === null || options === void 0 ? void 0 : options.fill) !== null && _options$fill !== void 0 ? _options$fill : ' ';
  const fillLength = maxLength - prefix.length - sufix.length - 2 * spaceAround - text.length;
  return [prefix, fill.repeat(Math.floor(fillLength / 2)), ` ${text} `, fill.repeat(Math.ceil(fillLength / 2)), sufix].join('');
}

;
const hostsConfiguration = `${printSection('Wazuh hosts', {
  prefix: '# ',
  fill: '-'
})}
#
# The following configuration is the default structure to define a host.
#
# hosts:
#   # Host ID / name,
#   - env-1:
#       # Host URL
#       url: https://env-1.example
#       # Host / API port
#       port: 55000
#       # Host / API username
#       username: wazuh-wui
#       # Host / API password
#       password: wazuh-wui
#       # Use RBAC or not. If set to true, the username must be "wazuh-wui".
#       run_as: true
#   - env-2:
#       url: https://env-2.example
#       port: 55000
#       username: wazuh-wui
#       password: wazuh-wui
#       run_as: true

hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: wazuh-wui
      run_as: false
`;
/**
 * Given a string, this function builds a multine string, each line about 70
 * characters long, splitted at the closest whitespace character to that lentgh.
 *
 * This function is used to transform the settings description
 * into a multiline string to be used as the setting documentation.
 *
 * The # character is also appended to the beginning of each line.
 *
 * @param text
 * @returns multine string
 */

exports.hostsConfiguration = hostsConfiguration;

function splitDescription(text = '') {
  const lines = text.match(/.{1,80}(?=\s|$)/g) || [];
  return lines.map(z => '# ' + z.trim()).join('\n');
}

const initialWazuhConfig = [header, pluginSettingsConfiguration, hostsConfiguration].join('\n#\n');
exports.initialWazuhConfig = initialWazuhConfig;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluaXRpYWwtd2F6dWgtY29uZmlnLnRzIl0sIm5hbWVzIjpbImhlYWRlciIsIlBMVUdJTl9BUFBfTkFNRSIsInByaW50U2VjdGlvbiIsInByZWZpeCIsImZpbGwiLCJwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb25GaWxlIiwiZmlsdGVyIiwiaXNDb25maWd1cmFibGVGcm9tRmlsZSIsInBsdWdpblNldHRpbmdzQ29uZmlndXJhdGlvbkZpbGVHcm91cEJ5Q2F0ZWdvcnkiLCJwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb24iLCJtYXAiLCJjYXRlZ29yeSIsImNhdGVnb3J5SUQiLCJzZXR0aW5ncyIsInByaW50U2V0dGluZ0NhdGVnb3J5IiwiUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVMiLCJwbHVnaW5TZXR0aW5nc09mQ2F0ZWdvcnkiLCJzZXR0aW5nIiwicHJpbnRTZXR0aW5nIiwiam9pbiIsInByaW50U2V0dGluZ1ZhbHVlIiwidmFsdWUiLCJKU09OIiwic3RyaW5naWZ5IiwibGVuZ3RoIiwic3BsaXREZXNjcmlwdGlvbiIsImtleSIsImRlZmF1bHRWYWx1ZSIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJ0ZXh0Iiwib3B0aW9ucyIsIm1heExlbmd0aCIsInN1Zml4Iiwic3VmZml4Iiwic3BhY2VBcm91bmQiLCJmaWxsTGVuZ3RoIiwicmVwZWF0IiwiTWF0aCIsImZsb29yIiwiY2VpbCIsImhvc3RzQ29uZmlndXJhdGlvbiIsImxpbmVzIiwibWF0Y2giLCJ6IiwidHJpbSIsImluaXRpYWxXYXp1aENvbmZpZyJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBWUE7O0FBS0E7O0FBQ0E7O0FBbEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFVTyxNQUFNQSxNQUFjLEdBQUk7QUFDL0I7QUFDQSxJQUFJQywwQkFBZ0I7QUFDcEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FB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QTs7OztBQUNPLFNBQVNxQixnQkFBVCxDQUEwQkssSUFBWSxHQUFHLEVBQXpDLEVBQXFEO0FBQzFELFFBQU1ZLEtBQUssR0FBR1osSUFBSSxDQUFDYSxLQUFMLENBQVcsa0JBQVgsS0FBa0MsRUFBaEQ7QUFDQSxTQUFPRCxLQUFLLENBQUNoQyxHQUFOLENBQVdrQyxDQUFELElBQU8sT0FBT0EsQ0FBQyxDQUFDQyxJQUFGLEVBQXhCLEVBQWtDMUIsSUFBbEMsQ0FBdUMsSUFBdkMsQ0FBUDtBQUNEOztBQUVNLE1BQU0yQixrQkFBMEIsR0FBRyxDQUFDOUMsTUFBRCxFQUFTUywyQkFBVCxFQUFzQ2dDLGtCQUF0QyxFQUEwRHRCLElBQTFELENBQStELE9BQS9ELENBQW5DIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIEFwcCBjb25maWd1cmF0aW9uIGZpbGVcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbmltcG9ydCB7XG4gIFBMVUdJTl9BUFBfTkFNRSxcbiAgUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVMsXG4gIFRQbHVnaW5TZXR0aW5nV2l0aEtleSxcbn0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBnZXRQbHVnaW5TZXR0aW5nRGVzY3JpcHRpb24sIGdldFNldHRpbmdzRGVmYXVsdExpc3QsIGdyb3VwU2V0dGluZ3NCeUNhdGVnb3J5IH0gZnJvbSAnLi4vLi4vY29tbW9uL3NlcnZpY2VzL3NldHRpbmdzJztcbmltcG9ydCB7IHdlYkRvY3VtZW50YXRpb25MaW5rIH0gZnJvbSAnLi4vLi4vY29tbW9uL3NlcnZpY2VzL3dlYl9kb2N1bWVudGF0aW9uJztcblxuZXhwb3J0IGNvbnN0IGhlYWRlcjogc3RyaW5nID0gYC0tLVxuI1xuIyAke1BMVUdJTl9BUFBfTkFNRX0gLSBBcHAgY29uZmlndXJhdGlvbiBmaWxlXG4jIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4jXG4jIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4jIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4jIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4jIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4jXG4jIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4jXG4ke3ByaW50U2VjdGlvbignV2F6dWggYXBwIGNvbmZpZ3VyYXRpb24gZmlsZScsIHsgcHJlZml4OiAnIyAnLCBmaWxsOiAnPScgfSl9XG4jXG4jIFBsZWFzZSBjaGVjayB0aGUgZG9jdW1lbnRhdGlvbiBmb3IgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCBjb25maWd1cmF0aW9uIG9wdGlvbnM6XG4jICR7d2ViRG9jdW1lbnRhdGlvbkxpbmsoJ3VzZXItbWFudWFsL3dhenVoLWRhc2hib2FyZC9jb25maWctZmlsZS5odG1sJyl9XG4jXG4jIEFsc28sIHlvdSBjYW4gY2hlY2sgb3VyIHJlcG9zaXRvcnk6XG4jIGh0dHBzOi8vZ2l0aHViLmNvbS93YXp1aC93YXp1aC1raWJhbmEtYXBwYDtcblxuY29uc3QgcGx1Z2luU2V0dGluZ3NDb25maWd1cmF0aW9uRmlsZSA9IGdldFNldHRpbmdzRGVmYXVsdExpc3QoKS5maWx0ZXIoKHsgaXNDb25maWd1cmFibGVGcm9tRmlsZSB9KSA9PiBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlKTtcblxuY29uc3QgcGx1Z2luU2V0dGluZ3NDb25maWd1cmF0aW9uRmlsZUdyb3VwQnlDYXRlZ29yeSA9IGdyb3VwU2V0dGluZ3NCeUNhdGVnb3J5KHBsdWdpblNldHRpbmdzQ29uZmlndXJhdGlvbkZpbGUpO1xuXG5jb25zdCBwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb24gPSBwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb25GaWxlR3JvdXBCeUNhdGVnb3J5Lm1hcCgoeyBjYXRlZ29yeTogY2F0ZWdvcnlJRCwgc2V0dGluZ3MgfSkgPT4ge1xuICBjb25zdCBjYXRlZ29yeSA9IHByaW50U2V0dGluZ0NhdGVnb3J5KFBMVUdJTl9TRVRUSU5HU19DQVRFR09SSUVTW2NhdGVnb3J5SURdKTtcblxuICBjb25zdCBwbHVnaW5TZXR0aW5nc09mQ2F0ZWdvcnkgPSBzZXR0aW5nc1xuICAgIC5tYXAoc2V0dGluZyA9PiBwcmludFNldHRpbmcoc2V0dGluZylcbiAgICApLmpvaW4oJ1xcbiNcXG4nKTtcbiAgLypcbiAgIy0tLS0tLS0tLS0tLS0tLS0tLS0ge2NhdGVnb3J5IG5hbWV9IC0tLS0tLS0tLS0tLS0tXG4gICNcbiAgIyAge2NhdGVnb3J5IGRlc2NyaXB0aW9ufVxuICAjXG4gICMge3NldHRpbmcgZGVzY3JpcHRpb259XG4gICMgc2V0dGluZ0tleTogc2V0dGluZ0RlZmF1bHRWYWx1ZVxuICAjXG4gICMge3NldHRpbmcgZGVzY3JpcHRpb259XG4gICMgc2V0dGluZ0tleTogc2V0dGluZ0RlZmF1bHRWYWx1ZVxuICAjIC4uLlxuICAqL1xuICByZXR1cm4gW2NhdGVnb3J5LCBwbHVnaW5TZXR0aW5nc09mQ2F0ZWdvcnldLmpvaW4oJ1xcbiNcXG4nKTtcbn0pLmpvaW4oJ1xcbiNcXG4nKTtcblxuXG5leHBvcnQgZnVuY3Rpb24gcHJpbnRTZXR0aW5nVmFsdWUodmFsdWU6IHVua25vd24pOiBhbnkge1xuICBpZiAodHlwZW9mIHZhbHVlID09PSAnb2JqZWN0Jykge1xuICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh2YWx1ZSlcbiAgfTtcblxuICBpZiAodHlwZW9mIHZhbHVlID09PSAnc3RyaW5nJyAmJiB2YWx1ZS5sZW5ndGggPT09IDApIHtcbiAgICByZXR1cm4gYCcnYFxuICB9O1xuXG4gIHJldHVybiB2YWx1ZTtcbn07XG5cbmV4cG9ydCBmdW5jdGlvbiBwcmludFNldHRpbmcoc2V0dGluZzogVFBsdWdpblNldHRpbmdXaXRoS2V5KTogc3RyaW5nIHtcbiAgLypcbiAgIyB7c2V0dGluZyBkZXNjcmlwdGlvbn1cbiAgIyB7c2V0dGluZ0tleX06IHtzZXR0aW5nRGVmYXVsdFZhbHVlfVxuICAqL1xuICByZXR1cm4gW1xuICAgIHNwbGl0RGVzY3JpcHRpb24oZ2V0UGx1Z2luU2V0dGluZ0Rlc2NyaXB0aW9uKHNldHRpbmcpKSxcbiAgICBgIyAke3NldHRpbmcua2V5fTogJHtwcmludFNldHRpbmdWYWx1ZShzZXR0aW5nLmRlZmF1bHRWYWx1ZSl9YFxuICBdLmpvaW4oJ1xcbicpXG59XG5cbmV4cG9ydCBmdW5jdGlvbiBwcmludFNldHRpbmdDYXRlZ29yeSh7IHRpdGxlLCBkZXNjcmlwdGlvbiB9KSB7XG4gIC8qXG4gICMtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHtjYXRlZ29yeSB0aXRsZX0gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAjIHtjYXRlZ29yeSBkZXNjcmlwdGlvbn1cbiAgI1xuICAqL1xuICByZXR1cm4gW1xuICAgIHByaW50U2VjdGlvbih0aXRsZSwgeyBwcmVmaXg6ICcjICcsIGZpbGw6ICctJyB9KSxcbiAgICAuLi4oZGVzY3JpcHRpb24gPyBbc3BsaXREZXNjcmlwdGlvbihkZXNjcmlwdGlvbildIDogWycnXSlcbiAgXS5qb2luKCdcXG4jXFxuJylcbn07XG5cbmV4cG9ydCBmdW5jdGlvbiBwcmludFNlY3Rpb24odGV4dDogc3RyaW5nLCBvcHRpb25zPzogeyBtYXhMZW5ndGg/OiBudW1iZXIsIHByZWZpeD86IHN0cmluZywgc3VmZml4Pzogc3RyaW5nLCBzcGFjZUFyb3VuZD86IG51bWJlciwgZmlsbD86IHN0cmluZyB9KSB7XG4gIGNvbnN0IG1heExlbmd0aCA9IG9wdGlvbnM/Lm1heExlbmd0aCA/PyA4MDtcbiAgY29uc3QgcHJlZml4ID0gb3B0aW9ucz8ucHJlZml4ID8/ICcnO1xuICBjb25zdCBzdWZpeCA9IG9wdGlvbnM/LnN1ZmZpeCA/PyAnJztcbiAgY29uc3Qgc3BhY2VBcm91bmQgPSBvcHRpb25zPy5zcGFjZUFyb3VuZCA/PyAxO1xuICBjb25zdCBmaWxsID0gb3B0aW9ucz8uZmlsbCA/PyAnICc7XG4gIGNvbnN0IGZpbGxMZW5ndGggPSBtYXhMZW5ndGggLSBwcmVmaXgubGVuZ3RoIC0gc3VmaXgubGVuZ3RoIC0gKDIgKiBzcGFjZUFyb3VuZCkgLSB0ZXh0Lmxlbmd0aDtcblxuICByZXR1cm4gW1xuICAgIHByZWZpeCxcbiAgICBmaWxsLnJlcGVhdChNYXRoLmZsb29yKGZpbGxMZW5ndGggLyAyKSksXG4gICAgYCAke3RleHR9IGAsXG4gICAgZmlsbC5yZXBlYXQoTWF0aC5jZWlsKGZpbGxMZW5ndGggLyAyKSksXG4gICAgc3VmaXhcbiAgXS5qb2luKCcnKTtcbn07XG5cbmV4cG9ydCBjb25zdCBob3N0c0NvbmZpZ3VyYXRpb24gPSBgJHtwcmludFNlY3Rpb24oJ1dhenVoIGhvc3RzJywgeyBwcmVmaXg6ICcjICcsIGZpbGw6ICctJyB9KX1cbiNcbiMgVGhlIGZvbGxvd2luZyBjb25maWd1cmF0aW9uIGlzIHRoZSBkZWZhdWx0IHN0cnVjdHVyZSB0byBkZWZpbmUgYSBob3N0LlxuI1xuIyBob3N0czpcbiMgICAjIEhvc3QgSUQgLyBuYW1lLFxuIyAgIC0gZW52LTE6XG4jICAgICAgICMgSG9zdCBVUkxcbiMgICAgICAgdXJsOiBodHRwczovL2Vudi0xLmV4YW1wbGVcbiMgICAgICAgIyBIb3N0IC8gQVBJIHBvcnRcbiMgICAgICAgcG9ydDogNTUwMDBcbiMgICAgICAgIyBIb3N0IC8gQVBJIHVzZXJuYW1lXG4jICAgICAgIHVzZXJuYW1lOiB3YXp1aC13dWlcbiMgICAgICAgIyBIb3N0IC8gQVBJIHBhc3N3b3JkXG4jICAgICAgIHBhc3N3b3JkOiB3YXp1aC13dWlcbiMgICAgICAgIyBVc2UgUkJBQyBvciBub3QuIElmIHNldCB0byB0cnVlLCB0aGUgdXNlcm5hbWUgbXVzdCBiZSBcIndhenVoLXd1aVwiLlxuIyAgICAgICBydW5fYXM6IHRydWVcbiMgICAtIGVudi0yOlxuIyAgICAgICB1cmw6IGh0dHBzOi8vZW52LTIuZXhhbXBsZVxuIyAgICAgICBwb3J0OiA1NTAwMFxuIyAgICAgICB1c2VybmFtZTogd2F6dWgtd3VpXG4jICAgICAgIHBhc3N3b3JkOiB3YXp1aC13dWlcbiMgICAgICAgcnVuX2FzOiB0cnVlXG5cbmhvc3RzOlxuICAtIGRlZmF1bHQ6XG4gICAgICB1cmw6IGh0dHBzOi8vbG9jYWxob3N0XG4gICAgICBwb3J0OiA1NTAwMFxuICAgICAgdXNlcm5hbWU6IHdhenVoLXd1aVxuICAgICAgcGFzc3dvcmQ6IHdhenVoLXd1aVxuICAgICAgcnVuX2FzOiBmYWxzZVxuYDtcblxuLyoqXG4gKiBHaXZlbiBhIHN0cmluZywgdGhpcyBmdW5jdGlvbiBidWlsZHMgYSBtdWx0aW5lIHN0cmluZywgZWFjaCBsaW5lIGFib3V0IDcwXG4gKiBjaGFyYWN0ZXJzIGxvbmcsIHNwbGl0dGVkIGF0IHRoZSBjbG9zZXN0IHdoaXRlc3BhY2UgY2hhcmFjdGVyIHRvIHRoYXQgbGVudGdoLlxuICpcbiAqIFRoaXMgZnVuY3Rpb24gaXMgdXNlZCB0byB0cmFuc2Zvcm0gdGhlIHNldHRpbmdzIGRlc2NyaXB0aW9uXG4gKiBpbnRvIGEgbXVsdGlsaW5lIHN0cmluZyB0byBiZSB1c2VkIGFzIHRoZSBzZXR0aW5nIGRvY3VtZW50YXRpb24uXG4gKlxuICogVGhlICMgY2hhcmFjdGVyIGlzIGFsc28gYXBwZW5kZWQgdG8gdGhlIGJlZ2lubmluZyBvZiBlYWNoIGxpbmUuXG4gKlxuICogQHBhcmFtIHRleHRcbiAqIEByZXR1cm5zIG11bHRpbmUgc3RyaW5nXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBzcGxpdERlc2NyaXB0aW9uKHRleHQ6IHN0cmluZyA9ICcnKTogc3RyaW5nIHtcbiAgY29uc3QgbGluZXMgPSB0ZXh0Lm1hdGNoKC8uezEsODB9KD89XFxzfCQpL2cpIHx8IFtdO1xuICByZXR1cm4gbGluZXMubWFwKCh6KSA9PiAnIyAnICsgei50cmltKCkpLmpvaW4oJ1xcbicpO1xufVxuXG5leHBvcnQgY29uc3QgaW5pdGlhbFdhenVoQ29uZmlnOiBzdHJpbmcgPSBbaGVhZGVyLCBwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb24sIGhvc3RzQ29uZmlndXJhdGlvbl0uam9pbignXFxuI1xcbicpO1xuIl19