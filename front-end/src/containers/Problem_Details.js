import React, { Component } from 'react';
import { NavLink,Link } from 'react-router-dom'
import brace from 'brace';
import AceEditor from 'react-ace';

import 'brace/mode/java';
import 'brace/theme/github';

export default class ProblemDetails extends Component {




      constructor(props) {
        super(props);
        this.state = {

        };
      }



      componentWillMount()
      {
        console.log(JSON.stringify(this.props));
        //********here we will GET DATA from redux to chekc if user authenticated o
        //********not
      }

     onChange = function(newValue) {
        console.log('change',newValue);
      }




  render() {
    return (

   <div className="container">
  <div className="row">
    <h3>problem name </h3>
  </div>

  <div className="row">
    <ul className="nav nav-tabs">
  <li className="active"><a href="#">Problem</a></li>
  <li><a href="#">Submissions</a></li>
  <li><a href="#">Leaderboard</a></li>
  <li><a href="#">Tutorial</a></li>
</ul>
  </div>



<div className="row">
  <AceEditor
    mode="java"
    theme="github"

    name="UNIQUE_ID_OF_DIV"
    editorProps={{$blockScrolling: true}}
  />

<button type="button" className="btn btn-warning">Submit</button>
<button type="button" className="btn btn-warning">Run the Code</button>
</div>


   </div>


    );
  }
}
