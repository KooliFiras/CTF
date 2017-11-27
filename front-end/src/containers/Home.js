import React, { Component } from 'react';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Leaderboard from './containers/Leaderboard' ;
import SignIN from './containers/SignIn';
import Signup from './containers/SignUp' ;
import Teams from './containers/Teams' ;
import Problems from './containers/Problems' ;

export default class Home extends Component {




      constructor(props) {
        super(props);
        this.state = {

        };
      }



      componentWillMount()
      {
        //********here we will GET DATA from redux to chekc if user authenticated o
        //********not
      }






  render() {
    return (
       <div classNameName="container">

         <div className="row">

             <ProblemCategory />
             <ProblemCategory />
             <ProblemCategory />
         </div>


         <div className="row">

             <ProblemCategory />
             <ProblemCategory />
             <ProblemCategory />
         </div>


        </div>
    );
  }
}
