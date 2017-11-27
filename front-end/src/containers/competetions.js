import React, { Component } from 'react';
import { Button } from 'react-bootstrap';

const io = require('socket.io-client')
const socket = io()

export default class Competetions extends Component {


  constructor(props) {
    super(props);
    this.state = {
competetions : []
    };
  }




  componentDidMount() {

    socket.on('competetions', function (data) {
       console.log(data);
       socket.emit('my other event', { my: 'data' });
     });
  }



  render() {
    return (
    <div className="container">


<div class="row">

<div class="alert alert-light" role="alert">
    All contests
</div>

</div>

<hr/>





      <div className="row">

   <div className="col-md-8">


  <ul className="list-group">


   <li className="list-group-item">
     <div className="alert alert-info">
  <div class="row">
        <div class="col-md-8">
     <h4 class="alert-heading">Contest Name!</h4>
     <p>conetst description </p>


       </div>

  </div>
    <div class="row">
      <div class="col-md-4">
       <button type="button" className="btn btn-success pull-right">Sign up</button>
       </div>
     </div>

     </div>


   </li>

<br/>
<br/>
<br/>


   <div className="panel panel-default">
      <div className="panel-heading">Contest Title</div>
      <div className="panel-body">Contest Description ABout start date , end date</div>
       <div class="panel-footer">
         <button type="button" className="btn btn-success pull-right">Sign up
         <i className="fa fa-check-square-o" aria-hidden="true"></i>

         </button>
       </div>
    </div>



 </ul>

   </div>


  <div className="col-md-4">

<div className="row">
  <Button bsStyle="primary" onClick={()=>{
      console.log('pressed');
      this.props.history.push('/CreateContest')
    }}>Create contest <i className="fa fa-plus" aria-hidden="true"></i></Button>
</div>





    <ul class="list-group">

   <li class="list-group-item">
     <div class="alert alert-light" role="alert">

       <div class="input-group">
            <label for="email">Problem solving    <input type="checkbox" aria-label="Checkbox for following text input" /></label>

        </div>

        </div>
   </li>


   <li class="list-group-item">
     <div class="alert alert-light" role="alert">

       <div class="input-group">
            <label for="email">Golang programming <input type="checkbox" aria-label="Checkbox for following text input" /></label>
        </div>

        </div>
   </li>



   <li class="list-group-item">
     <div class="alert alert-light" role="alert">

       <div class="input-group">
            <label for="email">Python programming  <input type="checkbox" aria-label="Checkbox for following text input" /></label>
        </div>

        </div>
   </li>

 </ul>


  </div>

    </div>
    </div>
    );
  }
}
