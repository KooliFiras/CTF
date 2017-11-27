import React, { Component } from 'react';
import ProblemCategory from '../components/ProblemCategory' ;
import axios from 'axios';
import { Button } from 'react-bootstrap';
import FaIconPack from 'react-icons/lib/fa'
import RichTextEditor from 'react-rte';
import TagsInput from 'react-tagsinput'
import ReactDOM from 'react-dom';
import {Editor, EditorState} from 'draft-js';
/*require('medium-editor/dist/css/medium-editor.css');
require('medium-editor/dist/css/themes/default.css');*/

// ES module
//import Editor from 'react-medium-editor';

export default class CreateProblem extends Component {




constructor(props) {
        super(props);
        this.state = {
        title :'',
         category :'',
         description: '',
         solutions :[],
         tags: [],
         file :'',
         submitted : false ,
         errors: new Map(),
         editorState: EditorState.createEmpty(),
         value : RichTextEditor.createEmptyValue(),
         statement : RichTextEditor.createEmptyValue(),
         inputFormat :RichTextEditor.createEmptyValue(),
         outputFormat :RichTextEditor.createEmptyValue(),
         contsraints :RichTextEditor.createEmptyValue(),
         challengeName : '',
         text :'',
         challengeDescription :'',
         challengeLevel :'',
         challengeType :'',
         challengeScore :Number,
         challengelanguage :'',


        };
      }



componentWillMount()
{
      let errors = new Map();
      errors.set('name', '');
      errors.set('description', '');
      errors.set('level', '');
      errors.set('type', '');
      errors.set('score', '');
      this.setState({errors: errors});
  }


//***********************************//
componentWillReceiveProps(nextProps) {
this.props.paneActions.textEditor.updateTextValue(this.state.value.toString('html'));
  const newValue = nextProps.paneData.getIn(['text_editor', 'value']);
  this.setState({statement: RichTextEditor.createValueFromString(newValue, 'html')});
    }



//********************************//
handleChange(text, medium) {
    this.setState({text: text});
  }

//**********************//
//onChange = (editorState) => this.setState({editorState});

//******************************//
onChange = (value) => {
  console.log("value" + value);
  this.setState({statement :value});
  if (this.props.onChange) {
    // Send the changes up to the parent component as an HTML string.
    // This is here to demonstrate using `.toString()` but in a real app it
    // would be better to avoid generating a string on each change.
    this.props.onChange(
      value.toString('html')
    );
  }
};


handleChange(tags) {
   this.setState({tags})
 }


handleChallengeType(e)
{
  console.log(e.target.value);
   this.setState({challengeType :value});
}


//*******************************//
renderErrorMsg(data) {
  console.log('data' + data);
  return (data  ? <ErrorMsg>
    {data }
  </ErrorMsg> : null);

}

//***********************************//
//****************************************//
checkName =(e)=>{
  let value = e.target.value;

  let errors = this.state.errors;
  let submitted = this.state.submitted ;

  if(submitted==true)
  {
    if(value =='')
    {
      console.log("empty password");
      errors.set('name','Challenge Name is empty! Please provide a name')
      this.setState({errors:errors})

    }else if(value.length<3)
    {
      console.log("name length min");
      errors.set('name','Challenge Name should be at least 3 characters long.')
      this.setState({errors:errors})
    }

  }

 this.setState({challengeName :value});
}


//*******function to check the type of problem
//*******
checkType = (e) =>{
  let value = e.target.value;
  console.log("value" + JSON.stringify(value));

   this.setState({ challengeType:value});
}


//****************************//
checkDescription = (e) =>{
  let value = e.target.value;
  console.log("value" + JSON.stringify(value));

   this.setState({ challengeDescription:value});

}


//****************************//
checkLevel = (e) =>{
  let value = e.target.value;
  console.log("value" + JSON.stringify(value));

   this.setState({ challengeLevel:value});

}

//**************************************//
checkScore = (e) =>{
let value = e.target.value;
console.log("value" + JSON.stringify(value));

this.setState({ challengeScore:value});
}





//**************************************//
checkLanguage = (e) =>{
let value = e.target.value;
console.log("value" + JSON.stringify(value));

this.setState({ challengelanguage:value});
}





//***************function to submit the problem***************//
CreateChallenge =( event)=>{
  event.preventDefault();
  this.setState({submitted :true})
  let challengeName = this.state.challengeName ;
  let challengeDescription = this.state.challengeDescription;
  let challengeLevel = this.state.challengeLevel ;
console.log("clicked ");

}




  render() {
let errors = this.state.errors



    return (
      <div className="container">

     <div className="row">

         <div className="alert alert-light" role="alert">

Create Challenge



         </div>

         </div>

         <hr/>



<br/>
<br/>


  <form className="form-inline" onSubmit={this.CreateChallenge} noValidate>

    <div className="row">
      <div className="col-md-4">
          <div className="form-group">
          <label for="description">Select Type of Challenge </label>
          </div>
        </div>

        <div className="col-md-8">
            <div className="form-group">
              <select onChange={(event) => this.checkType(event)}
                 value={this.state.challengeType} className="form-control" id="sel1">
       <option value="Problem Solving">Problem Solving</option>
       <option value="Web-Client">Web-Client</option>
       <option value="Web-Server">Web-Server</option>

     </select>
           </div>
         </div>

    </div>

<br />






      <div className="row">
        <div className="col-md-4">
            <div className="form-group">
            <label for="description">Select The Programming language </label>
            </div>
          </div>

          <div className="col-md-8">
              <div className="form-group">
                <select onChange={(event) => this.checkLanguage(event)}
                   value={this.state.challengelanguage} className="form-control" id="sel1">
         <option value="Python">Python</option>
         <option value="Java">Java</option>
         <option value="C++">C++</option>
          <option value="C">C</option>
          <option value="PHP">PHP</option>

       </select>
             </div>
           </div>

      </div>

  <br />






  <div className="row">

<div className="col-md-4">
    <div className="form-group">
      <label for="name">Challenge Name:</label>
      </div>
</div>

<div className="col-md-8">
        <div className="form-group">
      <input type="text" value={this.state.challengeName}
        className="form-control" id="name" onChange={(event) => this.checkName(event)} />
       </div>
</div>

  </div>

{ this.renderErrorMsg(errors.get('name'))}


<br />



<div className="row">
  <div className="col-md-4">
      <div className="form-group">
      <label for="description">Description</label>
      </div>
    </div>

    <div className="col-md-8">
        <div className="form-group">
       <textarea className="form-control"
         value={this.state.challengeDescription}
    onChange={(event) => this.checkDescription(event)}
         rows="5" id="description"></textarea>
       </div>
     </div>

</div>

{ this.renderErrorMsg(errors.get('description'))}


<br />

<div className="row">
  <div className="col-md-4">
      <div className="form-group">
      <label for="description">Challenge Difficulty </label>
      </div>
    </div>

    <div className="col-md-8">
        <div className="form-group">
          <select value={this.state.challengeLevel}
  onChange={(event) => this.checkLevel(event)}
             className="form-control" id="sel1">
   <option value="Easy">Easy</option>
   <option value="Medium">Medium</option>
   <option value="Hard">Hard</option>

 </select>
       </div>
     </div>

</div>

<br />




    <div className="row">

  <div className="col-md-4">
      <div className="form-group">
        <label for="score">Challenge Score:</label>
        </div>
  </div>

  <div className="col-md-8">
          <div className="form-group">
        <input type="number" value={this.state.challengeScore}
          className="form-control" id="score"
          onChange={(event) => this.checkScore(event)} />
         </div>
  </div>

    </div>

  { this.renderErrorMsg(errors.get('name'))}


  <br />











<br />

<div className="row">
  <div className="col-md-4">
      <div className="form-group">
      <label for="description">Problem Statement</label>
      </div>
    </div>

    <div className="col-md-8">
        <div className="form-group">

    </div>
  </div>

</div>

<br/>

  <div className="row">
    <div className="col-md-4">
        <div className="form-group">
        <label for="description">Problem Statement</label>
        </div>
      </div>

      <div className="col-md-8">
          <div className="form-group">
         <textarea className="form-control"
           value={this.state.challengeDescription}
      onChange={(event) => this.checkDescription(event)}
           rows="5" id="description"></textarea>
         </div>
       </div>

  </div>



  <br/>





    <div className="row">
      <div className="col-md-4">
          <div className="form-group">
          <label for="description">INput Format</label>
          </div>
        </div>

        <div className="col-md-8">
            <div className="form-group">
           <textarea className="form-control"
             value={this.state.challengeDescription}
        onChange={(event) => this.checkDescription(event)}
             rows="5" id="description"></textarea>
           </div>
         </div>

    </div>



    <br/>



      <div className="row">
        <div className="col-md-4">
            <div className="form-group">
            <label for="description">OutPut Format</label>
            </div>
          </div>

          <div className="col-md-8">
              <div className="form-group">
             <textarea className="form-control"
               value={this.state.challengeDescription}
          onChange={(event) => this.checkDescription(event)}
               rows="5" id="description"></textarea>
             </div>
           </div>

      </div>



      <br/>


<br />
<br />




<div className="row">
    <button type="submit" className="btn btn-success">Add</button>
</div>
  </form>




        </div>
    );
  }
}
