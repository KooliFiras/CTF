import React, { Component } from 'react';
import { connect } from 'react-redux'
var validator = require('email-validator');
import ErrorMsg from '../components/ErrorMsg' ;



export default class Signup extends Component {


        constructor(props) {
          super(props);
          this.state = {
            username :'',
            email :'',
            password :'',
            errors: new Map(),
            submitted :false,
            usernameused :false ,
          };
        }



componentWillMount()
{
  let errors = new Map();
    errors.set('username', '');
  errors.set('email', '');
  errors.set('password', '');

  this.setState({errors: errors});
}



CheckUsernameUnicty =(username)=>
{
//****here we will check username unicty
}


//*********function to check email unicty
CheckEmailunicity = (email )=>
{
  /*auth.fetchProvidersForEmail(email)
  .then(result=>{

  if(result==true)
  {
    this.setState({emailused:true})
    return true ;
  }else {
    return false ;
  }

  }).catch(data=>{
    console.log("error" + data);
  })*/
  return true ;
}




//**********Verify Username ******************//
//**********VERIFY EAMIL ********************//
verifyUsername = (e) => {
  //*********GET THE EERORS******************//
  //**********GET THE TABLE OF ERRORS **************//

  let value = e.target.value;
  let errors = this.state.errors;
  let submitted = this.state.submitted ;
    //**********Check data validity ************//



if(submitted==true)
{

          //**********Check data validity ************//
          if(e.target.value=='')
          {
            errors.set('username','Username is required.')
            this.setState({errors:errors})
          } else if ( this.state.usernameused==true){
            errors.set('username','Username used before ')
            this.setState({errors:errors})
          }else {
            errors.set('username','')
            this.setState({errors:errors})
          }
}


    //*************update the email attribute *************//
    this.setState({username:e.target.value})
}




//**********VERIFY EAMIL ********************//
verifyEmail = (e) => {
  //*********GET THE EERORS******************//
  //**********GET THE TABLE OF ERRORS **************//

  let value = e.target.value;
  let errors = this.state.errors;
  let submitted = this.state.submitted ;
    //**********Check data validity ************//
this.CheckEmailunicity(e.target.value);


if(submitted==true)
{

          //**********Check data validity ************//
          if(e.target.value=='')
          {
            errors.set('email','Email is required.')
            this.setState({errors:errors})
          }else if(!validator.validate(e.target.value))
          {
            errors.set('email','Invalid email ')
            this.setState({errors:errors})
          } else if ( this.state.emailused==true){
            errors.set('email','Email used before ')
            this.setState({errors:errors})
          }else {
            errors.set('email','')
            this.setState({errors:errors})
          }
}


    //*************update the email attribute *************//
    this.setState({email:e.target.value})
}








//****************Verify Password********************//
//**********VERIFY PASSWORD ********************//
verifyPassword = (e) => {
  //*********GET THE EERORS******************//
  //**********GET THE TABLE OF ERRORS **************//
  let errors = this.state.errors;
  let submitted = this.state.submitted ;
  let value = e.target.value;

if(submitted==true)
{
  if(value =='')
  {
    console.log("empty password");
    errors.set('password','Password is empty! Please provide a password')
    this.setState({errors:errors})
  }else if(value.length<6)
  {
    console.log("pasword lenegth");
    errors.set('password','Password should be at least 6 characters long.')
    this.setState({errors:errors})
  }else{
    errors.set('password','')
    this.setState({errors:errors})
  }
}



    //*************update the password attribute *************//
    this.setState({password:value})
}




//***********function when clikc the button
SignUp =( event)=>{
  event.preventDefault();
console.log('sign in with emai && password using redux');
//******SET SUBMITTED TO TRUE***********//
this.setState({submitted :true})
//*******GET THE DATA****************//
let email =  this.state.email ;
let username = this.state.username ;
let password = this.state.password ;
let errors = this.state.errors ;

//**********VALIDATE THE EMAIL*******************//
this.CheckEmailunicity(email);

if(email  =='')
{

errors.set('email','Email adress is required !')
this.setState({errors:errors})
}
else if(!validator.validate(email))
{

  errors.set('email','Invalid Email adress')
  this.setState({errors:errors})
}else if ( this.state.emailused==true)
{

  errors.set('email','Email used before ')
  this.setState({errors:errors})
}


//********VALIDATE THE USERNAME*****************//
if(username  =='')
{

errors.set('username','Username  required !')
this.setState({errors:errors})
}
else if ( this.state.usernameused==true)
{

  errors.set('email','Username used before ')
  this.setState({errors:errors})
}









//*********VALIDATE THE PASSWORD*******************//

if(password =='')
{
  errors.set('password','Password is empty! Please provide a password')
  this.setState({errors:errors})
}else if(password.length<6)
{
  errors.set('password','Password should be at least 6 characters long.')
  this.setState({errors:errors})
}else{
  errors.set('password','')
  this.setState({errors:errors})
}






//********if there is no error **************//
if(errors.get('email')=='' && errors.get('password')==''
&& errors.get('password'))
{
  //********everything is fine
  //********call redux and navigate to the next scene *******//
  Alert('eeverythings if fine !')
}




}







//*********Signin with github***************//
SignUpWithGithub =()=>{
  console.log('sign in with github');
}



//*******************************//

renderErrorMsg(data) {

  return (data  ? <ErrorMsg>
    {data }
  </ErrorMsg> : null);

}





  render() {
let errors = this.state.errors ;
    return (
      <div className="container">
    <h2 className="text-center">Sign up </h2>
    <form className="form-horizontal"
      onSubmit={this.SignUp} noValidate>
      <div className="form-group">
        <label className="control-label col-sm-2" for="username">Username :</label>
        <div className="col-sm-10">
          <input type="text" className="form-control" id="username"
             placeholder="Enter Username" name="username"
             value={this.state.username}
              onChange={(event) => this.verifyUsername(event)}/>
        </div>
      </div>

   { this.renderErrorMsg(errors.get('username'))}


      <div className="form-group">
        <label className="control-label col-sm-2" for="pwd">Email:</label>
        <div className="col-sm-10">
          <input type="email" className="form-control"
            id="pwd" placeholder="Enter Email" name="pwd"
            value={this.state.email}
             onChange={(event) => this.verifyEmail(event)} />
        </div>
      </div>

   { this.renderErrorMsg(errors.get('email'))}

      <div className="form-group">
        <label className="control-label col-sm-2" for="pwd">Password:</label>
        <div className="col-sm-10">
          <input type="password" className="form-control"
            id="pwd" placeholder="Enter password"
            name="pwd"
            value={this.state.password}
            onChange={(event) => this.verifyPassword(event)} />
        </div>
      </div>

   { this.renderErrorMsg(errors.get('password'))}


      <div className="form-group">
        <div className="col-sm-offset-2 col-sm-10">
          <button type="submit" className="btn btn-default">Sign Up</button>
        </div>
      </div>


      <div className="form-group">
        <div className="col-sm-offset-2 col-sm-10">
          <button type="submit" className="btn btn-default">Sign up wit Github</button>
        </div>
      </div>

    </form>
  </div>
    );
  }
}
