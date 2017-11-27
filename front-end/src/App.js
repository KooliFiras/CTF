import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter, Switch, Route, NavLink } from 'react-router-dom'
import { Redirect } from 'react-router'



import Navbar from './components/Navbar';
import Footer from './components/Footer';


import Leaderboard from './containers/Leaderboard' ;
import SignIN from './containers/SignIn';
import Signup from './containers/SignUp' ;
import Teams from './containers/Teams' ;
import Problems from './containers/Problems' ;
import Competetions from './containers/competetions' ;
import Profile from './containers/Profile' ;
import ContestCalendar from './containers/ContestsCalendar' ;
import UserProfile from './containers/userProfile' ;
import Problem_List from './containers/List_Problems' ;
import ProblemDetails from './containers/Problem_Details';
import CreateProblem from './containers/CreateProblem' ;
import CreateContest from './containers/CreateContest' ;
import CreateContest2  from  './containers/CreateContest2' ;
import  Breadcrumbs  from'react-breadcrumbs' ;
//*******************const**********************//
const io = require('socket.io-client')
const socket = io()


export default class App extends Component {


componentDidMount() {

  socket.on('news', function (data) {
     console.log(data);
     socket.emit('my other event', { my: 'data' });
   });
}


  render() {
    return (
      <div>

<Navbar />
<div className="container">



    <main>

        <Route exact path="/" component={SignIN} />
        <Route exact path="/Sign-in" component={SignIN} />
        <Route exact path="/Sign-up" component={Signup} />
        <Route exact path="/Profile" component={Profile} />
        <Route exact path="/Competetions" component={Competetions} />
        <Route exact path="/Practise" component={Problems} />
        <Route exact path="/Leaderboard" component={Leaderboard} />
        <Route exact path="/Calendar" component={ContestCalendar} />
        <Route exact path="/UserProfile" component={UserProfile} />
        <Route exact path="/Problem_list" component={Problem_List} something="foo" />
        <Route exact path="/Problem_Deatils" component={ProblemDetails} something="foo" />
        <Route exact path="/Create_Probelm" component={CreateProblem} />
        <Route name="CreateContest"  staticName={true} exact path="/CreateContest" component={CreateContest} />
        <Route name="CreateContest2"  staticName={true} exact path="/CreateContest/AddChallenge" component={CreateContest2} />
      </main>

  </div>
<br/>
<br/>
<br/>
<br/>
  <br/>
  <br/>
  <br/>
  <br/>
    <br/>
    <br/>
    <br/>
    <br/>
   <Footer />

      </div>
    );
  }
}
