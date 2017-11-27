import React, { Component } from 'react';
import ProblemCategory from '../components/ProblemCategory' ;
import { NavLink,Link } from 'react-router-dom'

export default class Problem_List extends Component {




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






  render() {
    return (
       <div className="container">


<div classNameName ="row">
  <div className="jumbotron">
  <h3 className="display-3">Category name</h3>
  <p className="lead">
    Challenges related to different programming languages (C, PHP, Java ...)

<p>You must solve a security problem in these challenges by developing a small script using your choice of programming language.</p>

Prerequisites:
- Knowledge of a programming language..</p>
</div>
</div>



<div className="row">

  <div class="alert alert-light" role="alert">
    <table className="table table-striped">
      <thead>
      <tr>
      <td className="active">Challenge's Name</td>
    <td className="active">Difficulty </td>
    <td className="active">Author</td>
    <td className="active">Number of points </td>

   </tr>
 </thead>
      <tbody>
      <tr>
       <td> 1 </td>
       <td>
           <Link to={{ pathname: '/Problem_Deatils', query: { id: 'id_list' } }} activeClassName="active">
             hacker foulen ben foulen
           </Link>
          </td>
       <td> 125.0 </td>
       <td> Cartaghe </td>
      </tr>


      <tr>
       <td> 1 </td>
       <td> hacker foulen ben foulen </td>
       <td> 125.0 </td>
       <td> Cartaghe </td>
      </tr>

      <tr>
       <td> 1 </td>
       <td> hacker foulen ben foulen </td>
       <td> 125.0 </td>
       <td> Cartaghe </td>
      </tr>
    </tbody>
   </table>
  </div>
</div>



        </div>
    );
  }
}
