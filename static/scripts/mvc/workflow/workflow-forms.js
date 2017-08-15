"use strict";define(["utils/utils","mvc/form/form-view","mvc/tool/tool-form-base"],function(e,t,a){return{Default:Backbone.View.extend({initialize:function(e){this.form=new t(e)}}),Tool:Backbone.View.extend({initialize:function(t){var o=this;this.workflow=t.workflow,this.node=t.node,this.node?(this.post_job_actions=this.node.post_job_actions||{},e.deepeach(t.inputs,function(t){t.type&&(-1!=["data","data_collection"].indexOf(t.type)?(t.type="hidden",t.info="Data input '"+t.name+"' ("+e.textify(t.extensions)+")",t.value={__class__:"RuntimeValue"}):t.fixed||(t.collapsible_value={__class__:"RuntimeValue"},t.is_workflow=t.options&&0==t.options.length||-1!=["integer","float"].indexOf(t.type)))}),e.deepeach(t.inputs,function(e){"conditional"==e.type&&(e.test_param.collapsible_value=void 0)}),this._makeSections(t),this.form=new a(e.merge(t,{text_enable:"Set in Advance",text_disable:"Set at Runtime",narrow:!0,initial_errors:!0,cls:"ui-portlet-narrow",postchange:function(t,a){var n=a.model.attributes,i={tool_id:n.id,tool_version:n.version,type:"tool",inputs:$.extend(!0,{},a.data.create())};Galaxy.emit.debug("tool-form-workflow::postchange()","Sending current state.",i),e.request({type:"POST",url:Galaxy.root+"api/workflows/build_module",data:i,success:function(e){a.update(e.config_form),a.errors(e.config_form),o.node.update_field_data(e),Galaxy.emit.debug("tool-form-workflow::postchange()","Received new model.",e),t.resolve()},error:function(e){Galaxy.emit.debug("tool-form-workflow::postchange()","Refresh request failed.",e),t.reject()}})}}))):Galaxy.emit.debug("tool-form-workflow::initialize()","Node not found in workflow.")},_makeSections:function(e){var t=e.inputs,a=e.datatypes,o=this.node.output_terminals&&Object.keys(this.node.output_terminals)[0];if(o){t.push({name:"pja__"+o+"__EmailAction",label:"Email notification",type:"boolean",value:String(Boolean(this.post_job_actions["EmailAction"+o])),ignore:"false",help:"An email notification will be sent when the job has completed.",payload:{host:window.location.host}}),t.push({name:"pja__"+o+"__DeleteIntermediatesAction",label:"Output cleanup",type:"boolean",value:String(Boolean(this.post_job_actions["DeleteIntermediatesAction"+o])),ignore:"false",help:"Upon completion of this step, delete non-starred outputs from completed workflow steps if they are no longer required as inputs."});for(var n in this.node.output_terminals)t.push(this._makeSection(n,a))}},_makeSection:function(e,t){function a(t,n){n=n||[],n.push(t);for(var i in t.inputs){var l=t.inputs[i];if(l.action){if(l.name="pja__"+e+"__"+l.action,l.pja_arg&&(l.name+="__"+l.pja_arg),l.payload)for(var s in l.payload)l.payload[l.name+"__"+s]=p,l.payload[s],delete l.payload[s];var r=o.post_job_actions[l.action+e];if(r){for(var u in n)n[u].expanded=!0;l.pja_arg?l.value=r.action_arguments&&r.action_arguments[l.pja_arg]||l.value:l.value="true"}}l.inputs&&a(l,n.slice(0))}}var o=this,n=[],i=[];for(key in t)n.push({0:t[key],1:t[key]});for(key in this.node.input_terminals)i.push(this.node.input_terminals[key].name);n.sort(function(e,t){return e.label>t.label?1:e.label<t.label?-1:0}),n.unshift({0:"Sequences",1:"Sequences"}),n.unshift({0:"Roadmaps",1:"Roadmaps"}),n.unshift({0:"Leave unchanged",1:"__empty__"});var l={title:"Configure Output: '"+e+"'",type:"section",flat:!0,inputs:[{label:"Label",type:"text",value:(output=this.node.getWorkflowOutput(e))&&output.label||"",help:"This will provide a short name to describe the output - this must be unique across workflows.",onchange:function(t){o.workflow.attemptUpdateOutputLabel(o.node,e,t)}},{action:"RenameDatasetAction",pja_arg:"newname",label:"Rename dataset",type:"text",value:"",ignore:"",help:'This action will rename the output dataset. Click <a href="https://galaxyproject.org/learn/advanced-workflow/variables/">here</a> for more information. Valid inputs are: <strong>'+i.join(", ")+"</strong>."},{action:"ChangeDatatypeAction",pja_arg:"newtype",label:"Change datatype",type:"select",ignore:"__empty__",value:"__empty__",options:n,help:"This action will change the datatype of the output to the indicated value."},{action:"TagDatasetAction",pja_arg:"tags",label:"Add Tags",type:"text",value:"",ignore:"",help:"This action will set tags for the dataset."},{action:"RemoveTagDatasetAction",pja_arg:"tags",label:"Remove Tags",type:"text",value:"",ignore:"",help:"This action will remove tags for the dataset."},{title:"Assign columns",type:"section",flat:!0,inputs:[{action:"ColumnSetAction",pja_arg:"chromCol",label:"Chrom column",type:"integer",value:"",ignore:""},{action:"ColumnSetAction",pja_arg:"startCol",label:"Start column",type:"integer",value:"",ignore:""},{action:"ColumnSetAction",pja_arg:"endCol",label:"End column",type:"integer",value:"",ignore:""},{action:"ColumnSetAction",pja_arg:"strandCol",label:"Strand column",type:"integer",value:"",ignore:""},{action:"ColumnSetAction",pja_arg:"nameCol",label:"Name column",type:"integer",value:"",ignore:""}],help:"This action will set column assignments in the output dataset. Blank fields are ignored."}]};return a(l),l}})}});
//# sourceMappingURL=../../../maps/mvc/workflow/workflow-forms.js.map
