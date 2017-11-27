import React, { Component } from 'react';

export default class Notifications extends Component {
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
               <a className="navbar-brand" href="#">Hacker Bootstrap Theme</a>
           </div>
           <div id="navbar" className="navbar-collapse collapse">
               <ul className="nav navbar-nav navbar-right">
                   <li className="dropdown">
                       <a href="#" className="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">CLICK ME!!!<span className="caret"></span> </a>
                       <ul className="dropdown-menu" role="menu">
                           <li><a href="#">Ooh a link</a></li>
                           <li><a href="#">Two links?! Oh boy</a></li>
                           <li><a href="#">Now you're being ridiculous</a></li>
                           <li className="divider"></li>
                           <li className="dropdown-header">Much Wow</li>
                           <li><a href="#">So link</a></li>
                           <li><a href="#">Many internet</a></li>
                       </ul>
                   </li>
                   <li>
                       <a href="//reddit.com/r/itsaunixsystem" target="_blank">H4x0rs Only</a>
                   </li>
               </ul>
           </div>
       </div>
   </nav>
    );
  }
}
