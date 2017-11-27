import React, { Component } from 'react';
import { NavLink,Link } from 'react-router-dom'


export default class ProblemCategory extends Component {




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


           <div className="col-md-4">
             <div className="panel panel-default">
               <div className="panel-heading">
                 <Link  to={{ pathname: '/Problem_list', query: { id: 'id_list' } }}><h3>
                   <i className="fa fa-lock" aria-hidden="true"></i> {this.props.categoryName} </h3> </Link>

               </div>
                  <div className="panel-body">
                   <p>{this.props.categoryMessage} </p>
                    </div>
                    </div>
               </div>


    );
  }
}
