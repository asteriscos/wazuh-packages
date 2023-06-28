(window["wazuh_bundle_jsonpfunction"]=window["wazuh_bundle_jsonpfunction"]||[]).push([[27],{1539:function(module,__webpack_exports__,__webpack_require__){"use strict";__webpack_require__.r(__webpack_exports__);__webpack_require__.d(__webpack_exports__,"default",(function(){return FilterLabel}));var react__WEBPACK_IMPORTED_MODULE_0__=__webpack_require__(9);var react__WEBPACK_IMPORTED_MODULE_0___default=__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);var _elastic_eui__WEBPACK_IMPORTED_MODULE_1__=__webpack_require__(102);var _elastic_eui__WEBPACK_IMPORTED_MODULE_1___default=__webpack_require__.n(_elastic_eui__WEBPACK_IMPORTED_MODULE_1__);var _osd_i18n__WEBPACK_IMPORTED_MODULE_2__=__webpack_require__(103);var _osd_i18n__WEBPACK_IMPORTED_MODULE_2___default=__webpack_require__.n(_osd_i18n__WEBPACK_IMPORTED_MODULE_2__);var _filter_operators__WEBPACK_IMPORTED_MODULE_3__=__webpack_require__(364);var _common__WEBPACK_IMPORTED_MODULE_4__=__webpack_require__(122);function FilterLabel(_ref){var filter=_ref.filter,valueLabel=_ref.valueLabel,filterLabelStatus=_ref.filterLabelStatus;var prefixText=filter.meta.negate?" ".concat(_osd_i18n__WEBPACK_IMPORTED_MODULE_2__["i18n"].translate("data.filter.filterBar.negatedFilterPrefix",{defaultMessage:"NOT "})):"";var prefix=filter.meta.negate&&!filter.meta.disabled?react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(_elastic_eui__WEBPACK_IMPORTED_MODULE_1__["EuiTextColor"],{color:"danger"},prefixText):prefixText;var getValue=function getValue(text){return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement("span",{className:"globalFilterLabel__value"},text)};if(filter.meta.alias!==null){return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,filter.meta.alias,filterLabelStatus&&react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0___default.a.Fragment,null,": ",getValue(valueLabel)))}switch(filter.meta.type){case _common__WEBPACK_IMPORTED_MODULE_4__["e"].EXISTS:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,filter.meta.key,": ",getValue("".concat(_filter_operators__WEBPACK_IMPORTED_MODULE_3__["b"].message)));case _common__WEBPACK_IMPORTED_MODULE_4__["e"].GEO_BOUNDING_BOX:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,filter.meta.key,": ",getValue(valueLabel));case _common__WEBPACK_IMPORTED_MODULE_4__["e"].GEO_POLYGON:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,filter.meta.key,": ",getValue(valueLabel));case _common__WEBPACK_IMPORTED_MODULE_4__["e"].PHRASES:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,filter.meta.key,": ",getValue("".concat(_filter_operators__WEBPACK_IMPORTED_MODULE_3__["c"].message," ").concat(valueLabel)));case _common__WEBPACK_IMPORTED_MODULE_4__["e"].QUERY_STRING:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,getValue("".concat(valueLabel)));case _common__WEBPACK_IMPORTED_MODULE_4__["e"].PHRASE:case _common__WEBPACK_IMPORTED_MODULE_4__["e"].RANGE:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,filter.meta.key,": ",getValue(valueLabel));default:return react__WEBPACK_IMPORTED_MODULE_0___default.a.createElement(react__WEBPACK_IMPORTED_MODULE_0__["Fragment"],null,prefix,getValue("".concat(JSON.stringify(filter.query)||filter.meta.value)))}}},364:function(module,__webpack_exports__,__webpack_require__){"use strict";__webpack_require__.d(__webpack_exports__,"c",(function(){return isOneOfOperator}));__webpack_require__.d(__webpack_exports__,"b",(function(){return existsOperator}));__webpack_require__.d(__webpack_exports__,"a",(function(){return FILTER_OPERATORS}));var _osd_i18n__WEBPACK_IMPORTED_MODULE_0__=__webpack_require__(103);var _osd_i18n__WEBPACK_IMPORTED_MODULE_0___default=__webpack_require__.n(_osd_i18n__WEBPACK_IMPORTED_MODULE_0__);var _common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__=__webpack_require__(172);var isOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.isOperatorOptionLabel",{defaultMessage:"is"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].PHRASE,negate:false};var isNotOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.isNotOperatorOptionLabel",{defaultMessage:"is not"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].PHRASE,negate:true};var isOneOfOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.isOneOfOperatorOptionLabel",{defaultMessage:"is one of"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].PHRASES,negate:false,fieldTypes:["string","number","date","ip","geo_point","geo_shape"]};var isNotOneOfOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.isNotOneOfOperatorOptionLabel",{defaultMessage:"is not one of"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].PHRASES,negate:true,fieldTypes:["string","number","date","ip","geo_point","geo_shape"]};var isBetweenOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.isBetweenOperatorOptionLabel",{defaultMessage:"is between"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].RANGE,negate:false,fieldTypes:["number","date","ip"]};var isNotBetweenOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.isNotBetweenOperatorOptionLabel",{defaultMessage:"is not between"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].RANGE,negate:true,fieldTypes:["number","date","ip"]};var existsOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.existsOperatorOptionLabel",{defaultMessage:"exists"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].EXISTS,negate:false};var doesNotExistOperator={message:_osd_i18n__WEBPACK_IMPORTED_MODULE_0__["i18n"].translate("data.filter.filterEditor.doesNotExistOperatorOptionLabel",{defaultMessage:"does not exist"}),type:_common_opensearch_query_filters__WEBPACK_IMPORTED_MODULE_1__["a"].EXISTS,negate:true};var FILTER_OPERATORS=[isOperator,isNotOperator,isOneOfOperator,isNotOneOfOperator,isBetweenOperator,isNotBetweenOperator,existsOperator,doesNotExistOperator]}}]);