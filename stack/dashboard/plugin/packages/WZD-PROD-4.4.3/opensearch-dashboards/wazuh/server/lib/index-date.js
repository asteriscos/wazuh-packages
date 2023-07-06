"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.indexDate = indexDate;

/*
 * Wazuh app - Module to get the index name according to date interval
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
function indexDate(interval) {
  try {
    if (!interval) throw new Error('Creation interval not found');
    const d = new Date().toISOString().replace(/T/, '-').replace(/\..+/, '').replace(/-/g, '.').replace(/:/g, '');
    let date = '';

    switch (interval) {
      case 'h':
        date = d.slice(0, -4) + 'h';
        break;

      case 'd':
        date = d.slice(0, -7);
        break;

      case 'w':
        date = d.slice(0, -12) + weekOfYear() + 'w';
        break;

      case 'm':
        date = d.slice(0, -10);
        break;

      default:
        throw new Error('Creation interval not found');
    }

    return date;
  } catch (error) {
    return new Date().toISOString().replace(/T/, '-').replace(/\..+/, '').replace(/-/g, '.').replace(/:/g, '').slice(0, -7);
  }
}

function weekOfYear() {
  var d = new Date();
  d.setHours(0, 0, 0);
  d.setDate(d.getDate() + 4 - (d.getDay() || 7));
  return Math.ceil(((d - new Date(d.getFullYear(), 0, 1)) / 8.64e7 + 1) / 7);
}

;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LWRhdGUudHMiXSwibmFtZXMiOlsiaW5kZXhEYXRlIiwiaW50ZXJ2YWwiLCJFcnJvciIsImQiLCJEYXRlIiwidG9JU09TdHJpbmciLCJyZXBsYWNlIiwiZGF0ZSIsInNsaWNlIiwid2Vla09mWWVhciIsImVycm9yIiwic2V0SG91cnMiLCJzZXREYXRlIiwiZ2V0RGF0ZSIsImdldERheSIsIk1hdGgiLCJjZWlsIiwiZ2V0RnVsbFllYXIiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRU8sU0FBU0EsU0FBVCxDQUFtQkMsUUFBbkIsRUFBNEQ7QUFDakUsTUFBSTtBQUNGLFFBQUksQ0FBQ0EsUUFBTCxFQUFlLE1BQU0sSUFBSUMsS0FBSixDQUFVLDZCQUFWLENBQU47QUFDZixVQUFNQyxDQUFDLEdBQUcsSUFBSUMsSUFBSixHQUNQQyxXQURPLEdBRVBDLE9BRk8sQ0FFQyxHQUZELEVBRU0sR0FGTixFQUdQQSxPQUhPLENBR0MsTUFIRCxFQUdTLEVBSFQsRUFJUEEsT0FKTyxDQUlDLElBSkQsRUFJTyxHQUpQLEVBS1BBLE9BTE8sQ0FLQyxJQUxELEVBS08sRUFMUCxDQUFWO0FBTUEsUUFBSUMsSUFBSSxHQUFHLEVBQVg7O0FBQ0EsWUFBUU4sUUFBUjtBQUNFLFdBQUssR0FBTDtBQUNFTSxRQUFBQSxJQUFJLEdBQUdKLENBQUMsQ0FBQ0ssS0FBRixDQUFRLENBQVIsRUFBVyxDQUFDLENBQVosSUFBaUIsR0FBeEI7QUFDQTs7QUFDRixXQUFLLEdBQUw7QUFDRUQsUUFBQUEsSUFBSSxHQUFHSixDQUFDLENBQUNLLEtBQUYsQ0FBUSxDQUFSLEVBQVcsQ0FBQyxDQUFaLENBQVA7QUFDQTs7QUFDRixXQUFLLEdBQUw7QUFDRUQsUUFBQUEsSUFBSSxHQUFHSixDQUFDLENBQUNLLEtBQUYsQ0FBUSxDQUFSLEVBQVcsQ0FBQyxFQUFaLElBQWtCQyxVQUFVLEVBQTVCLEdBQWlDLEdBQXhDO0FBQ0E7O0FBQ0YsV0FBSyxHQUFMO0FBQ0VGLFFBQUFBLElBQUksR0FBR0osQ0FBQyxDQUFDSyxLQUFGLENBQVEsQ0FBUixFQUFXLENBQUMsRUFBWixDQUFQO0FBQ0E7O0FBQ0Y7QUFDRSxjQUFNLElBQUlOLEtBQUosQ0FBVSw2QkFBVixDQUFOO0FBZEo7O0FBZ0JBLFdBQU9LLElBQVA7QUFDRCxHQTFCRCxDQTBCRSxPQUFPRyxLQUFQLEVBQWM7QUFDZCxXQUFPLElBQUlOLElBQUosR0FDSkMsV0FESSxHQUVKQyxPQUZJLENBRUksR0FGSixFQUVTLEdBRlQsRUFHSkEsT0FISSxDQUdJLE1BSEosRUFHWSxFQUhaLEVBSUpBLE9BSkksQ0FJSSxJQUpKLEVBSVUsR0FKVixFQUtKQSxPQUxJLENBS0ksSUFMSixFQUtVLEVBTFYsRUFNSkUsS0FOSSxDQU1FLENBTkYsRUFNSyxDQUFDLENBTk4sQ0FBUDtBQU9EO0FBQ0Y7O0FBRUQsU0FBU0MsVUFBVCxHQUE4QjtBQUM1QixNQUFJTixDQUFDLEdBQUcsSUFBSUMsSUFBSixFQUFSO0FBQ0FELEVBQUFBLENBQUMsQ0FBQ1EsUUFBRixDQUFXLENBQVgsRUFBYyxDQUFkLEVBQWlCLENBQWpCO0FBQ0FSLEVBQUFBLENBQUMsQ0FBQ1MsT0FBRixDQUFVVCxDQUFDLENBQUNVLE9BQUYsS0FBYyxDQUFkLElBQW1CVixDQUFDLENBQUNXLE1BQUYsTUFBYyxDQUFqQyxDQUFWO0FBQ0EsU0FBT0MsSUFBSSxDQUFDQyxJQUFMLENBQVUsQ0FBQyxDQUFDYixDQUFDLEdBQUcsSUFBSUMsSUFBSixDQUFTRCxDQUFDLENBQUNjLFdBQUYsRUFBVCxFQUEwQixDQUExQixFQUE2QixDQUE3QixDQUFMLElBQXdDLE1BQXhDLEdBQWlELENBQWxELElBQXVELENBQWpFLENBQVA7QUFDRDs7QUFBQSIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgdG8gZ2V0IHRoZSBpbmRleCBuYW1lIGFjY29yZGluZyB0byBkYXRlIGludGVydmFsXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG5leHBvcnQgZnVuY3Rpb24gaW5kZXhEYXRlKGludGVydmFsOiAnaCcgfCAnZCcgfCAndycgfCAnbScpOiBzdHJpbmcge1xuICB0cnkge1xuICAgIGlmICghaW50ZXJ2YWwpIHRocm93IG5ldyBFcnJvcignQ3JlYXRpb24gaW50ZXJ2YWwgbm90IGZvdW5kJyk7XG4gICAgY29uc3QgZCA9IG5ldyBEYXRlKClcbiAgICAgIC50b0lTT1N0cmluZygpXG4gICAgICAucmVwbGFjZSgvVC8sICctJylcbiAgICAgIC5yZXBsYWNlKC9cXC4uKy8sICcnKVxuICAgICAgLnJlcGxhY2UoLy0vZywgJy4nKVxuICAgICAgLnJlcGxhY2UoLzovZywgJycpO1xuICAgIGxldCBkYXRlID0gJyc7XG4gICAgc3dpdGNoIChpbnRlcnZhbCkge1xuICAgICAgY2FzZSAnaCc6XG4gICAgICAgIGRhdGUgPSBkLnNsaWNlKDAsIC00KSArICdoJztcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdkJzpcbiAgICAgICAgZGF0ZSA9IGQuc2xpY2UoMCwgLTcpO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ3cnOlxuICAgICAgICBkYXRlID0gZC5zbGljZSgwLCAtMTIpICsgd2Vla09mWWVhcigpICsgJ3cnO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ20nOlxuICAgICAgICBkYXRlID0gZC5zbGljZSgwLCAtMTApO1xuICAgICAgICBicmVhaztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQ3JlYXRpb24gaW50ZXJ2YWwgbm90IGZvdW5kJyk7XG4gICAgfVxuICAgIHJldHVybiBkYXRlO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHJldHVybiBuZXcgRGF0ZSgpXG4gICAgICAudG9JU09TdHJpbmcoKVxuICAgICAgLnJlcGxhY2UoL1QvLCAnLScpXG4gICAgICAucmVwbGFjZSgvXFwuLisvLCAnJylcbiAgICAgIC5yZXBsYWNlKC8tL2csICcuJylcbiAgICAgIC5yZXBsYWNlKC86L2csICcnKVxuICAgICAgLnNsaWNlKDAsIC03KTtcbiAgfVxufVxuXG5mdW5jdGlvbiB3ZWVrT2ZZZWFyKCk6IG51bWJlciB7XG4gIHZhciBkID0gbmV3IERhdGUoKTtcbiAgZC5zZXRIb3VycygwLCAwLCAwKTtcbiAgZC5zZXREYXRlKGQuZ2V0RGF0ZSgpICsgNCAtIChkLmdldERheSgpIHx8IDcpKTtcbiAgcmV0dXJuIE1hdGguY2VpbCgoKGQgLSBuZXcgRGF0ZShkLmdldEZ1bGxZZWFyKCksIDAsIDEpKSAvIDguNjRlNyArIDEpIC8gNyk7XG59O1xuIl19