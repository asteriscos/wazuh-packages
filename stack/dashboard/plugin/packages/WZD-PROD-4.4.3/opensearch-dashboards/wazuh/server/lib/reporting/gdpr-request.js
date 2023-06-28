"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.topGDPRRequirements = exports.getRulesByRequirement = void 0;

var _baseQuery = require("./base-query");

var _settings = require("../../../common/services/settings");

/*
 * Wazuh app - Specific methods to fetch Wazuh GDPR data from Elasticsearch
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

/**
 * Returns top 5 GDPR requirements
 * @param {*} context Endpoint context
 * @param {Number} gte Timestamp (ms) from
 * @param {Number} lte Timestamp (ms) to
 * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
 * @returns {Array<String>}
 */
const topGDPRRequirements = async (context, gte, lte, filters, allowedAgentsFilter, pattern = (0, _settings.getSettingDefaultValue)('pattern')) => {
  if (filters.includes('rule.gdpr: exists')) {
    const [head, tail] = filters.split('AND rule.gdpr: exists');
    filters = head + tail;
  }

  ;

  try {
    const base = {};
    Object.assign(base, (0, _baseQuery.Base)(pattern, filters, gte, lte, allowedAgentsFilter));
    Object.assign(base.aggs, {
      '2': {
        terms: {
          field: 'rule.gdpr',
          size: 5,
          order: {
            _count: 'desc'
          }
        }
      }
    });
    base.query.bool.must.push({
      exists: {
        field: 'rule.gdpr'
      }
    });
    const response = await context.core.opensearch.client.asCurrentUser.search({
      index: pattern,
      body: base
    });
    const {
      buckets
    } = response.body.aggregations['2'];
    return buckets.map(item => item.key);
  } catch (error) {
    return Promise.reject(error);
  }
};
/**
 * Returns top 3 rules for specific GDPR requirement
 * @param {*} context Endpoint context
 * @param {Number} gte Timestamp (ms) from
 * @param {Number} lte Timestamp (ms) to
 * @param {String} requirement GDPR requirement. E.g: 'II_5.1.F'
 * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
 * @returns {Array<String>}
 */


exports.topGDPRRequirements = topGDPRRequirements;

const getRulesByRequirement = async (context, gte, lte, filters, allowedAgentsFilter, requirement, pattern = (0, _settings.getSettingDefaultValue)('pattern')) => {
  if (filters.includes('rule.gdpr: exists')) {
    const [head, tail] = filters.split('AND rule.gdpr: exists');
    filters = head + tail;
  }

  ;

  try {
    const base = {};
    Object.assign(base, (0, _baseQuery.Base)(pattern, filters, gte, lte, allowedAgentsFilter));
    Object.assign(base.aggs, {
      '2': {
        terms: {
          field: 'rule.description',
          size: 3,
          order: {
            _count: 'desc'
          }
        },
        aggs: {
          '3': {
            terms: {
              field: 'rule.id',
              size: 1,
              order: {
                _count: 'desc'
              }
            }
          }
        }
      }
    });
    base.query.bool.must[0].query_string.query = base.query.bool.must[0].query_string.query + ` AND rule.gdpr: "${requirement}"`;
    const response = await context.core.opensearch.client.asCurrentUser.search({
      index: pattern,
      body: base
    });
    const {
      buckets
    } = response.body.aggregations['2'];
    return buckets.reduce((accum, bucket) => {
      if (!bucket || !bucket['3'] || !bucket['3'].buckets || !bucket['3'].buckets[0] || !bucket['3'].buckets[0].key || !bucket.key) {
        return accum;
      }

      ;
      accum.push({
        ruleID: bucket['3'].buckets[0].key,
        ruleDescription: bucket.key
      });
      return accum;
    }, []);
  } catch (error) {
    return Promise.reject(error);
  }
};

exports.getRulesByRequirement = getRulesByRequirement;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImdkcHItcmVxdWVzdC50cyJdLCJuYW1lcyI6WyJ0b3BHRFBSUmVxdWlyZW1lbnRzIiwiY29udGV4dCIsImd0ZSIsImx0ZSIsImZpbHRlcnMiLCJhbGxvd2VkQWdlbnRzRmlsdGVyIiwicGF0dGVybiIsImluY2x1ZGVzIiwiaGVhZCIsInRhaWwiLCJzcGxpdCIsImJhc2UiLCJPYmplY3QiLCJhc3NpZ24iLCJhZ2dzIiwidGVybXMiLCJmaWVsZCIsInNpemUiLCJvcmRlciIsIl9jb3VudCIsInF1ZXJ5IiwiYm9vbCIsIm11c3QiLCJwdXNoIiwiZXhpc3RzIiwicmVzcG9uc2UiLCJjb3JlIiwib3BlbnNlYXJjaCIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJzZWFyY2giLCJpbmRleCIsImJvZHkiLCJidWNrZXRzIiwiYWdncmVnYXRpb25zIiwibWFwIiwiaXRlbSIsImtleSIsImVycm9yIiwiUHJvbWlzZSIsInJlamVjdCIsImdldFJ1bGVzQnlSZXF1aXJlbWVudCIsInJlcXVpcmVtZW50IiwicXVlcnlfc3RyaW5nIiwicmVkdWNlIiwiYWNjdW0iLCJidWNrZXQiLCJydWxlSUQiLCJydWxlRGVzY3JpcHRpb24iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUlBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTyxNQUFNQSxtQkFBbUIsR0FBRyxPQUNqQ0MsT0FEaUMsRUFFakNDLEdBRmlDLEVBR2pDQyxHQUhpQyxFQUlqQ0MsT0FKaUMsRUFLakNDLG1CQUxpQyxFQU1qQ0MsT0FBTyxHQUFHLHNDQUF1QixTQUF2QixDQU51QixLQU85QjtBQUNILE1BQUlGLE9BQU8sQ0FBQ0csUUFBUixDQUFpQixtQkFBakIsQ0FBSixFQUEyQztBQUN6QyxVQUFNLENBQUNDLElBQUQsRUFBT0MsSUFBUCxJQUFlTCxPQUFPLENBQUNNLEtB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QUFDREEsTUFBQUEsS0FBSyxDQUFDdEIsSUFBTixDQUFXO0FBQUV3QixRQUFBQSxNQUFNLEVBQUVELE1BQU0sQ0FBQyxHQUFELENBQU4sQ0FBWWIsT0FBWixDQUFvQixDQUFwQixFQUF1QkksR0FBakM7QUFBc0NXLFFBQUFBLGVBQWUsRUFBRUYsTUFBTSxDQUFDVDtBQUE5RCxPQUFYO0FBQ0EsYUFBT1EsS0FBUDtBQUNELEtBYk0sRUFhSixFQWJJLENBQVA7QUFjRCxHQWxERCxDQWtERSxPQUFPUCxLQUFQLEVBQWM7QUFDZCxXQUFPQyxPQUFPLENBQUNDLE1BQVIsQ0FBZUYsS0FBZixDQUFQO0FBQ0Q7QUFDRixDQW5FTSIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBTcGVjaWZpYyBtZXRob2RzIHRvIGZldGNoIFdhenVoIEdEUFIgZGF0YSBmcm9tIEVsYXN0aWNzZWFyY2hcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5pbXBvcnQgeyBCYXNlIH0gZnJvbSAnLi9iYXNlLXF1ZXJ5JztcbmltcG9ydCB7IGdldFNldHRpbmdEZWZhdWx0VmFsdWUgfSBmcm9tICcuLi8uLi8uLi9jb21tb24vc2VydmljZXMvc2V0dGluZ3MnO1xuXG4vKipcbiAqIFJldHVybnMgdG9wIDUgR0RQUiByZXF1aXJlbWVudHNcbiAqIEBwYXJhbSB7Kn0gY29udGV4dCBFbmRwb2ludCBjb250ZXh0XG4gKiBAcGFyYW0ge051bWJlcn0gZ3RlIFRpbWVzdGFtcCAobXMpIGZyb21cbiAqIEBwYXJhbSB7TnVtYmVyfSBsdGUgVGltZXN0YW1wIChtcykgdG9cbiAqIEBwYXJhbSB7U3RyaW5nfSBmaWx0ZXJzIEUuZzogY2x1c3Rlci5uYW1lOiB3YXp1aCBBTkQgcnVsZS5ncm91cHM6IHZ1bG5lcmFiaWxpdHlcbiAqIEByZXR1cm5zIHtBcnJheTxTdHJpbmc+fVxuICovXG5leHBvcnQgY29uc3QgdG9wR0RQUlJlcXVpcmVtZW50cyA9IGFzeW5jIChcbiAgY29udGV4dCxcbiAgZ3RlLFxuICBsdGUsXG4gIGZpbHRlcnMsXG4gIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gIHBhdHRlcm4gPSBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCdwYXR0ZXJuJylcbikgPT4ge1xuICBpZiAoZmlsdGVycy5pbmNsdWRlcygncnVsZS5nZHByOiBleGlzdHMnKSkge1xuICAgIGNvbnN0IFtoZWFkLCB0YWlsXSA9IGZpbHRlcnMuc3BsaXQoJ0FORCBydWxlLmdkcHI6IGV4aXN0cycpO1xuICAgIGZpbHRlcnMgPSBoZWFkICsgdGFpbDtcbiAgfTtcblxuICB0cnkge1xuICAgIGNvbnN0IGJhc2UgPSB7fTtcblxuICAgIE9iamVjdC5hc3NpZ24oYmFzZSwgQmFzZShwYXR0ZXJuLCBmaWx0ZXJzLCBndGUsIGx0ZSwgYWxsb3dlZEFnZW50c0ZpbHRlcikpO1xuXG4gICAgT2JqZWN0LmFzc2lnbihiYXNlLmFnZ3MsIHtcbiAgICAgICcyJzoge1xuICAgICAgICB0ZXJtczoge1xuICAgICAgICAgIGZpZWxkOiAncnVsZS5nZHByJyxcbiAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgIG9yZGVyOiB7XG4gICAgICAgICAgICBfY291bnQ6ICdkZXNjJ1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgYmFzZS5xdWVyeS5ib29sLm11c3QucHVzaCh7XG4gICAgICBleGlzdHM6IHtcbiAgICAgICAgZmllbGQ6ICdydWxlLmdkcHInXG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGNvbnRleHQuY29yZS5vcGVuc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaCh7XG4gICAgICBpbmRleDogcGF0dGVybixcbiAgICAgIGJvZHk6IGJhc2VcbiAgICB9KTtcbiAgICBjb25zdCB7IGJ1Y2tldHMgfSA9IHJlc3BvbnNlLmJvZHkuYWdncmVnYXRpb25zWycyJ107XG5cbiAgICByZXR1cm4gYnVja2V0cy5tYXAoaXRlbSA9PiBpdGVtLmtleSk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgfVxufVxuXG4vKipcbiAqIFJldHVybnMgdG9wIDMgcnVsZXMgZm9yIHNwZWNpZmljIEdEUFIgcmVxdWlyZW1lbnRcbiAqIEBwYXJhbSB7Kn0gY29udGV4dCBFbmRwb2ludCBjb250ZXh0XG4gKiBAcGFyYW0ge051bWJlcn0gZ3RlIFRpbWVzdGFtcCAobXMpIGZyb21cbiAqIEBwYXJhbSB7TnVtYmVyfSBsdGUgVGltZXN0YW1wIChtcykgdG9cbiAqIEBwYXJhbSB7U3RyaW5nfSByZXF1aXJlbWVudCBHRFBSIHJlcXVpcmVtZW50LiBFLmc6ICdJSV81LjEuRidcbiAqIEBwYXJhbSB7U3RyaW5nfSBmaWx0ZXJzIEUuZzogY2x1c3Rlci5uYW1lOiB3YXp1aCBBTkQgcnVsZS5ncm91cHM6IHZ1bG5lcmFiaWxpdHlcbiAqIEByZXR1cm5zIHtBcnJheTxTdHJpbmc+fVxuICovXG5leHBvcnQgY29uc3QgZ2V0UnVsZXNCeVJlcXVpcmVtZW50ID0gYXN5bmMgKFxuICBjb250ZXh0LFxuICBndGUsXG4gIGx0ZSxcbiAgZmlsdGVycyxcbiAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgcmVxdWlyZW1lbnQsXG4gIHBhdHRlcm4gPSBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCdwYXR0ZXJuJylcbikgPT4ge1xuICBpZiAoZmlsdGVycy5pbmNsdWRlcygncnVsZS5nZHByOiBleGlzdHMnKSkge1xuICAgIGNvbnN0IFtoZWFkLCB0YWlsXSA9IGZpbHRlcnMuc3BsaXQoJ0FORCBydWxlLmdkcHI6IGV4aXN0cycpO1xuICAgIGZpbHRlcnMgPSBoZWFkICsgdGFpbDtcbiAgfTtcblxuICB0cnkge1xuICAgIGNvbnN0IGJhc2UgPSB7fTtcblxuICAgIE9iamVjdC5hc3NpZ24oYmFzZSwgQmFzZShwYXR0ZXJuLCBmaWx0ZXJzLCBndGUsIGx0ZSwgYWxsb3dlZEFnZW50c0ZpbHRlcikpO1xuXG4gICAgT2JqZWN0LmFzc2lnbihiYXNlLmFnZ3MsIHtcbiAgICAgICcyJzoge1xuICAgICAgICB0ZXJtczoge1xuICAgICAgICAgIGZpZWxkOiAncnVsZS5kZXNjcmlwdGlvbicsXG4gICAgICAgICAgc2l6ZTogMyxcbiAgICAgICAgICBvcmRlcjoge1xuICAgICAgICAgICAgX2NvdW50OiAnZGVzYydcbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IHtcbiAgICAgICAgICAnMyc6IHtcbiAgICAgICAgICAgIHRlcm1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5pZCcsXG4gICAgICAgICAgICAgIHNpemU6IDEsXG4gICAgICAgICAgICAgIG9yZGVyOiB7XG4gICAgICAgICAgICAgICAgX2NvdW50OiAnZGVzYydcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgYmFzZS5xdWVyeS5ib29sLm11c3RbMF0ucXVlcnlfc3RyaW5nLnF1ZXJ5ID1cbiAgICAgIGJhc2UucXVlcnkuYm9vbC5tdXN0WzBdLnF1ZXJ5X3N0cmluZy5xdWVyeSArIGAgQU5EIHJ1bGUuZ2RwcjogXCIke3JlcXVpcmVtZW50fVwiYDtcblxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgY29udGV4dC5jb3JlLm9wZW5zZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuc2VhcmNoKHtcbiAgICAgIGluZGV4OiBwYXR0ZXJuLFxuICAgICAgYm9keTogYmFzZVxuICAgIH0pO1xuICAgIGNvbnN0IHsgYnVja2V0cyB9ID0gcmVzcG9uc2UuYm9keS5hZ2dyZWdhdGlvbnNbJzInXTtcbiAgICByZXR1cm4gYnVja2V0cy5yZWR1Y2UoKGFjY3VtLCBidWNrZXQpID0+IHtcbiAgICAgIGlmIChcbiAgICAgICAgIWJ1Y2tldCB8fFxuICAgICAgICAhYnVja2V0WyczJ10gfHxcbiAgICAgICAgIWJ1Y2tldFsnMyddLmJ1Y2tldHMgfHxcbiAgICAgICAgIWJ1Y2tldFsnMyddLmJ1Y2tldHNbMF0gfHxcbiAgICAgICAgIWJ1Y2tldFsnMyddLmJ1Y2tldHNbMF0ua2V5IHx8XG4gICAgICAgICFidWNrZXQua2V5XG4gICAgICApIHtcbiAgICAgICAgcmV0dXJuIGFjY3VtO1xuICAgICAgfTtcbiAgICAgIGFjY3VtLnB1c2goeyBydWxlSUQ6IGJ1Y2tldFsnMyddLmJ1Y2tldHNbMF0ua2V5LCBydWxlRGVzY3JpcHRpb246IGJ1Y2tldC5rZXkgfSk7XG4gICAgICByZXR1cm4gYWNjdW07XG4gICAgfSwgW10pO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gIH1cbn1cbiJdfQ==