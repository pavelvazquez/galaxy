"use strict";define(["utils/utils","mvc/ui/ui-tabs","mvc/ui/ui-misc","mvc/form/form-view"],function(t,e,a,s){return{View:Backbone.View.extend({initialize:function(){this.setElement("<div/>"),this.model=new Backbone.Model({dataset_id:Galaxy.params.dataset_id}),this.render()},render:function(){var e=Galaxy.root+"dataset/edit",a=this;t.get({url:e,data:{dataset_id:a.model.get("dataset_id")},success:function(t){a.render_attribute_page(a,t)},error:function(t){var e={status:"error",message:"Error occured while loading the dataset.",persistent:!0,cls:"errormessage"};a.display_message(e,a.$(".response-message"))}})},render_attribute_page:function(t,e){var a={message:e.message,status:e.status,persistent:!0,cls:e.status+"message"};t.$el.empty().append(t._templateHeader()),t.display_message(a,t.$(".response-message")),t.create_tabs(e,t.$(".edit-attr"))},call_ajax:function(t,e,a){var s=Galaxy.root+"dataset/edit";$.ajax({type:"PUT",url:s,data:e,success:function(e){t.render_attribute_page(t,e),t.reload_history()},error:function(e){var a={status:"error",message:"Error occured while saving. Please fill all the required fields and try again.",persistent:!0,cls:"errormessage"};t.display_message(a,t.$(".response-message"))}})},display_message:function(t,e){e.empty().html(new a.Message(t).$el)},create_tabs:function(t,a){var s=this;s.tabs=new e.View,s.tabs.add({id:"attributes",title:"Attributes",icon:"fa fa-bars",tooltip:"Edit dataset attributes",$el:s._getAttributesFormTemplate(t)}),s.tabs.add({id:"convert",title:"Convert",icon:"fa-gear",tooltip:"Convert to new format",$el:s._getConvertFormTemplate(t)}),s.tabs.add({id:"datatype",title:"Datatypes",icon:"fa-database",tooltip:"Change data type",$el:s._getChangeDataTypeFormTemplate(t)}),s.tabs.add({id:"permissions",title:"Permissions",icon:"fa-user",tooltip:"Permissions",$el:s._getPermissionsFormTemplate(t)}),a.append(s.tabs.$el),s.tabs.showTab("attributes")},_templateHeader:function(){return'<div class="page-container edit-attr"><div class="response-message"></div><h3>Edit Dataset Attributes</h3></div>'},_getAttributesFormTemplate:function(t){var e=this,i=new s({title:"Edit attributes",inputs:t.edit_attributes_inputs,operations:{submit_editattr:new a.ButtonIcon({tooltip:"Save attributes of the dataset.",icon:"fa-floppy-o ",title:"Save attributes",onclick:function(){e._submit(e,i,t,"edit_attributes")}}),submit_autocorrect:new a.ButtonIcon({tooltip:"This will inspect the dataset and attempt to correct the values of fields if they are not accurate.",icon:"fa-undo ",title:"Auto-detect",onclick:function(){e._submit(e,i,t,"auto-detect")}})}});return i.$el},_getConvertFormTemplate:function(t){var e=this,i=new s({title:"Convert to new format",inputs:t.convert_inputs,operations:{submit:new a.ButtonIcon({tooltip:"Convert the datatype to a new format.",title:"Convert datatype",icon:"fa-exchange ",onclick:function(){e._submit(e,i,t,"convert")}})}});return i.$el},_getChangeDataTypeFormTemplate:function(t){var e=this,i=new s({title:"Change datatype",inputs:t.convert_datatype_inputs,operations:{submit:new a.ButtonIcon({tooltip:"Change the datatype to a new type.",title:"Change datatype",icon:"fa-exchange ",onclick:function(){e._submit(e,i,t,"change")}})}});return i.$el},_getPermissionsFormTemplate:function(t){var e=this;if(t.can_manage_dataset){var i=new s({title:"Manage dataset permissions on "+t.display_name,inputs:t.permission_inputs,operations:{submit:new a.ButtonIcon({tooltip:"Save permissions.",title:"Save permissions",icon:"fa-floppy-o ",onclick:function(){e._submit(e,i,t,"permissions")}})}});return i.$el}var i=new s({title:"View permissions",inputs:t.permission_inputs});return i.$el},_submit:function(t,e,a,s){var i=e.data.create();switch(i.dataset_id=a.dataset_id,s){case"edit_attributes":i.save="Save";break;case"auto-detect":i.detect="Auto-detect";break;case"convert":null!==i.target_type&&i.target_type&&(i.dataset_id=a.dataset_id,i.convert_data="Convert");break;case"change":i.change="Save";break;case"permissions":var n={};n.permissions=JSON.stringify(i),n.update_roles_button="Save",n.dataset_id=a.dataset_id,i=n}t.call_ajax(t,i)},reload_history:function(){window.Galaxy&&window.Galaxy.currHistoryPanel.loadCurrentHistory()}})}});
//# sourceMappingURL=../../../maps/mvc/dataset/dataset-edit-attributes.js.map
