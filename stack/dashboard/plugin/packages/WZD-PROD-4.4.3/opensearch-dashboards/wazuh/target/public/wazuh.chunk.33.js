(window["wazuh_bundle_jsonpfunction"]=window["wazuh_bundle_jsonpfunction"]||[]).push([[33],{1784:function(module,__webpack_exports__,__webpack_require__){"use strict";__webpack_require__.r(__webpack_exports__);__webpack_require__.d(__webpack_exports__,"default",(function(){return suggestions_component_SuggestionsComponent}));var external_osdSharedDeps_Lodash_=__webpack_require__(22);var external_osdSharedDeps_React_=__webpack_require__(9);var external_osdSharedDeps_React_default=__webpack_require__.n(external_osdSharedDeps_React_);var classnames=__webpack_require__(131);var classnames_default=__webpack_require__.n(classnames);var external_osdSharedDeps_StyledComponents_=__webpack_require__(119);var external_osdSharedDeps_StyledComponents_default=__webpack_require__.n(external_osdSharedDeps_StyledComponents_);var external_osdSharedDeps_ElasticEui_=__webpack_require__(102);function getEuiIconType(type){switch(type){case"field":return"kqlField";case"value":return"kqlValue";case"recentSearch":return"search";case"conjunction":return"kqlSelector";case"operator":return"kqlOperand";default:throw new Error("Unknown type: ".concat(type))}}function SuggestionComponent(props){return external_osdSharedDeps_React_default.a.createElement("div",{className:classnames_default()({osdTypeahead__item:true,active:props.selected}),role:"option",onClick:function onClick(){return props.onClick(props.suggestion)},onMouseEnter:props.onMouseEnter,ref:props.innerRef,id:props.ariaId,"aria-selected":props.selected,"data-test-subj":"autocompleteSuggestion-".concat(props.suggestion.type,"-").concat(props.suggestion.text.replace(/\s/g,"-"))},external_osdSharedDeps_React_default.a.createElement("div",{className:"osdSuggestionItem osdSuggestionItem--"+props.suggestion.type},external_osdSharedDeps_React_default.a.createElement("div",{className:"osdSuggestionItem__type"},external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_["EuiIcon"],{type:getEuiIconType(props.suggestion.type)})),external_osdSharedDeps_React_default.a.createElement("div",{className:"osdSuggestionItem__text","data-test-subj":"autoCompleteSuggestionText"},props.suggestion.text),props.shouldDisplayDescription&&external_osdSharedDeps_React_default.a.createElement("div",{className:"osdSuggestionItem__description"},props.suggestion.description)))}var SUGGESTIONS_LIST_REQUIRED_WIDTH=600;var SUGGESTIONS_LIST_REQUIRED_BOTTOM_SPACE=250;var SUGGESTIONS_LIST_REQUIRED_TOP_OFFSET=1;function _typeof(obj){"@babel/helpers - typeof";return _typeof="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(obj){return typeof obj}:function(obj){return obj&&"function"==typeof Symbol&&obj.constructor===Symbol&&obj!==Symbol.prototype?"symbol":typeof obj},_typeof(obj)}function _classCallCheck(instance,Constructor){if(!(instance instanceof Constructor)){throw new TypeError("Cannot call a class as a function")}}function _defineProperties(target,props){for(var i=0;i<props.length;i++){var descriptor=props[i];descriptor.enumerable=descriptor.enumerable||false;descriptor.configurable=true;if("value"in descriptor)descriptor.writable=true;Object.defineProperty(target,descriptor.key,descriptor)}}function _createClass(Constructor,protoProps,staticProps){if(protoProps)_defineProperties(Constructor.prototype,protoProps);if(staticProps)_defineProperties(Constructor,staticProps);Object.defineProperty(Constructor,"prototype",{writable:false});return Constructor}function _inherits(subClass,superClass){if(typeof superClass!=="function"&&superClass!==null){throw new TypeError("Super expression must either be null or a function")}subClass.prototype=Object.create(superClass&&superClass.prototype,{constructor:{value:subClass,writable:true,configurable:true}});Object.defineProperty(subClass,"prototype",{writable:false});if(superClass)_setPrototypeOf(subClass,superClass)}function _setPrototypeOf(o,p){_setPrototypeOf=Object.setPrototypeOf||function _setPrototypeOf(o,p){o.__proto__=p;return o};return _setPrototypeOf(o,p)}function _createSuper(Derived){var hasNativeReflectConstruct=_isNativeReflectConstruct();return function _createSuperInternal(){var Super=_getPrototypeOf(Derived),result;if(hasNativeReflectConstruct){var NewTarget=_getPrototypeOf(this).constructor;result=Reflect.construct(Super,arguments,NewTarget)}else{result=Super.apply(this,arguments)}return _possibleConstructorReturn(this,result)}}function _possibleConstructorReturn(self,call){if(call&&(_typeof(call)==="object"||typeof call==="function")){return call}else if(call!==void 0){throw new TypeError("Derived constructors may only return object or undefined")}return _assertThisInitialized(self)}function _assertThisInitialized(self){if(self===void 0){throw new ReferenceError("this hasn't been initialised - super() hasn't been called")}return self}function _isNativeReflectConstruct(){if(typeof Reflect==="undefined"||!Reflect.construct)return false;if(Reflect.construct.sham)return false;if(typeof Proxy==="function")return true;try{Boolean.prototype.valueOf.call(Reflect.construct(Boolean,[],(function(){})));return true}catch(e){return false}}function _getPrototypeOf(o){_getPrototypeOf=Object.setPrototypeOf?Object.getPrototypeOf:function _getPrototypeOf(o){return o.__proto__||Object.getPrototypeOf(o)};return _getPrototypeOf(o)}function _defineProperty(obj,key,value){if(key in obj){Object.defineProperty(obj,key,{value:value,enumerable:true,configurable:true,writable:true})}else{obj[key]=value}return obj}var suggestions_component_SuggestionsComponent=function(_Component){_inherits(SuggestionsComponent,_Component);var _super=_createSuper(SuggestionsComponent);function SuggestionsComponent(){var _this;_classCallCheck(this,SuggestionsComponent);for(var _len=arguments.length,args=new Array(_len),_key=0;_key<_len;_key++){args[_key]=arguments[_key]}_this=_super.call.apply(_super,[this].concat(args));_defineProperty(_assertThisInitialized(_this),"childNodes",[]);_defineProperty(_assertThisInitialized(_this),"parentNode",null);_defineProperty(_assertThisInitialized(_this),"scrollIntoView",(function(){if(_this.props.index===null){return}var parent=_this.parentNode;var child=_this.childNodes[_this.props.index];if(_this.props.index==null||!parent||!child){return}var scrollTop=Math.max(Math.min(parent.scrollTop,child.offsetTop),child.offsetTop+child.offsetHeight-parent.offsetHeight);parent.scrollTop=scrollTop}));_defineProperty(_assertThisInitialized(_this),"handleScroll",(function(){if(!_this.props.loadMore||!_this.parentNode){return}var position=_this.parentNode.scrollTop+_this.parentNode.offsetHeight;var height=_this.parentNode.scrollHeight;var remaining=height-position;var margin=50;if(!height||!position){return}if(remaining<=margin){_this.props.loadMore()}}));return _this}_createClass(SuggestionsComponent,[{key:"render",value:function render(){var _this2=this,_classNames;if(!this.props.queryBarRect||!this.props.show||Object(external_osdSharedDeps_Lodash_["isEmpty"])(this.props.suggestions)){return null}var suggestions=this.props.suggestions.map((function(suggestion,index){var isDescriptionFittable=_this2.props.queryBarRect.width>=SUGGESTIONS_LIST_REQUIRED_WIDTH;return external_osdSharedDeps_React_default.a.createElement(SuggestionComponent,{innerRef:function innerRef(node){return _this2.childNodes[index]=node},selected:index===_this2.props.index,suggestion:suggestion,onClick:_this2.props.onClick,onMouseEnter:function onMouseEnter(){return _this2.props.onMouseEnter(index)},ariaId:"suggestion-"+index,key:"".concat(suggestion.type," - ").concat(suggestion.text),shouldDisplayDescription:isDescriptionFittable})}));var documentHeight=document.documentElement.clientHeight||window.innerHeight;var queryBarRect=this.props.queryBarRect;var isSuggestionsListFittable=documentHeight-(queryBarRect.top+queryBarRect.height)>SUGGESTIONS_LIST_REQUIRED_BOTTOM_SPACE;var verticalListPosition=isSuggestionsListFittable?"top: ".concat(window.scrollY+queryBarRect.bottom-SUGGESTIONS_LIST_REQUIRED_TOP_OFFSET,"px;"):"bottom: ".concat(documentHeight-(window.scrollY+queryBarRect.top),"px;");return external_osdSharedDeps_React_default.a.createElement(StyledSuggestionsListDiv,{queryBarRect:queryBarRect,verticalListPosition:verticalListPosition},external_osdSharedDeps_React_default.a.createElement("div",{className:classnames_default()("osdTypeahead",{"osdTypeahead--small":this.props.size==="s"})},external_osdSharedDeps_React_default.a.createElement("div",{className:classnames_default()("osdTypeahead__popover",(_classNames={},_defineProperty(_classNames,"osdTypeahead__popover--bottom",isSuggestionsListFittable),_defineProperty(_classNames,"osdTypeahead__popover--top",!isSuggestionsListFittable),_classNames))},external_osdSharedDeps_React_default.a.createElement("div",{id:"osdTypeahead__items",role:"listbox",ref:function ref(node){return _this2.parentNode=node},onScroll:this.handleScroll},suggestions))))}},{key:"componentDidUpdate",value:function componentDidUpdate(prevProps){if(prevProps.index!==this.props.index){this.scrollIntoView()}}}]);return SuggestionsComponent}(external_osdSharedDeps_React_["Component"]);var StyledSuggestionsListDiv=external_osdSharedDeps_StyledComponents_default.a.div.withConfig({displayName:"StyledSuggestionsListDiv",componentId:"sc-b1tlry-0"})(["",""],(function(props){return"\n      position: absolute;\n      z-index: 4001;\n      left: ".concat(props.queryBarRect.left,"px;\n      width: ").concat(props.queryBarRect.width,"px;\n      ").concat(props.verticalListPosition)}))}}]);