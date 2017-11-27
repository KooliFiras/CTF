import React from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter, Switch, Route, NavLink ,IndexRoute} from 'react-router-dom'
import { Redirect } from 'react-router'

//******************redux imports********************//
import { createStore, applyMiddleware } from 'redux'
import { Provider } from 'react-redux'
import thunkMiddleware from 'redux-thunk'



import App from './App';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Leaderboard from './containers/Leaderboard' ;
import {SignIN}  from './containers/SignIn';
import Signup from './containers/SignUp' ;
import Teams from './containers/Teams' ;
import Competetions from './containers/competetions' ;
import Problems from './containers/Problems' ;
import NotFound from './components/NotFound' ;

/*
<Route path="/protected" component={() => (fakeAuth.isAuthenticated ? (<Protected />) : (<Redirect to={{pathname: '/login',state: { from: '/protected'}
}}/>))} />
 */
/*
<BrowserRouter>
   <div>


     <Switch>
         <Route path="/" component={App} exact={true} />
       <Route path="/Sign-in" component={SignIN} />
       <Route path="/Sign-up" component={Signup} />
       <Route path="/Leaderboard" component={Leaderboard} />
       <Route path="/Problems" component={Problems} />
       <Route path="/Competetions" component={Competetions} />
       <Route component={NotFound}/>
     </Switch>
   </div>
</BrowserRouter>
 */

ReactDOM.render(<BrowserRouter>
  <App/>
 </BrowserRouter>, document.getElementById('root'));
