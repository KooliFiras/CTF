import React, { Component } from 'react';
import { NavLink,Link } from 'react-router-dom'
import { connect } from 'react-redux'

export default class Navbar extends Component {


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
      <nav className="navbar navbar-default navbar-static-top">
       <div className="container">
           <div className="navbar-header">
               <button type="button" className="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                   <span className="sr-only">Toggle navigation</span>
                   <span className="icon-bar"></span>
                   <span className="icon-bar"></span>
                   <span className="icon-bar"></span>
               </button>
               <a className="navbar-brand" href="#">Capture the Flag</a>
           </div>
           <div id="navbar" className="navbar-collapse collapse">
               <ul className="nav navbar-nav navbar-right">

                   <li>
                  <Link to="/Sign-in" activeClassName="active">
                      <i className="fa fa-sign-in" aria-hidden="true"></i>
                    Sign-in
                  </Link>

                   </li>


                   <li>
                  <Link to="/Sign-up" activeClassName="active">
                    <i className="fa fa-user-plus" aria-hidden="true"></i>
                    Sign-Up
                    </Link>
                   </li>


                   <li>
                  <Link to="/Competetions" activeClassName="active">
                    <i className="fa fa-archive" aria-hidden="true"></i>
                    Compete
                    </Link>
                   </li>


                   <li>
                  <Link to="/Practise" activeClassName="active">
                      <i className="fa fa-trophy" aria-hidden="true"></i>
                    Practise
                    </Link>
                   </li>


                   <li>
                  <Link to="/Leaderboard" activeClassName="active">
                    <i className="fa fa-trophy" aria-hidden="true"></i>
                    Leaderboard
                    </Link>
                   </li>


                   <li>
                  <Link to="/Profile" activeClassName="active">
                      <i className="fa fa-user" aria-hidden="true"></i>
                    Profile
                    </Link>
                   </li>

                   <li className="dropdown">
                       <a href="#" className="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">Profile<span className="caret"></span> </a>
                       <ul className="dropdown-menu" role="menu">
                           <li>

                             <a href="#"><i className="fa fa-user" aria-hidden="true"></i>
                             Account
                           </a>

                             </li>
                           <li><a href="#">
                                <i className="fa fa-flag" aria-hidden="true"></i>
                             Notifications</a></li>
                           <li><a href="#">
                             <i className="fa fa-comments" aria-hidden="true"></i>
                             Messages</a></li>
                           <li className="divider"></li>
                           <li>
                             <a href="#">
                               <i className="fa fa-sign-out" aria-hidden="true"></i>
                             Sign-out</a>

                              </li>
                       </ul>
                   </li>


               </ul>
           </div>
       </div>
   </nav>
    );
  }
}
