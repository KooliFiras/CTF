import React, { Component } from 'react';
import ProblemCategory from '../components/ProblemCategory' ;
import axios from 'axios';
import { Button } from 'react-bootstrap';
import FaIconPack from 'react-icons/lib/fa'

export default class Problems extends Component {




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
           <h3 className="text-center"> Practise Programming</h3>

</div>
<div className="row ">
   <div className="pull-right">
  <Button bsStyle="primary" onClick={()=>{
      console.log('pressed');
      this.props.history.push('/Create_Probelm')
    }}>Create A problem <i className="fa fa-plus" aria-hidden="true"></i>  </Button>

  <p> (conditional rendering if the type of user is admin) </p>
  </div>
</div>


<br/>
<br/>
<br/>

         <div className="row">

             <ProblemCategory categoryName="Programming"
               categoryMessage="simpleMsghere" />
             <ProblemCategory
               categoryName="Python "
                 categoryMessage="Web-Client" />
             <ProblemCategory
               categoryName="Script Shell"
                 categoryMessage="simpleMsghere"/>
         </div>


         <div className="row">

             <ProblemCategory categoryName="Network"
               categoryMessage="simpleMsghere" />
             <ProblemCategory categoryName="Web-server"
               categoryMessage="simpleMsghere"/>
             <ProblemCategory  categoryName="Web-Client"
               categoryMessage="simpleMsghere"/>
         </div>


         <div className="row">

             <ProblemCategory categoryName="CryptAnalysis"
               categoryMessage="simpleMsghere" />
             <ProblemCategory categoryName="Steganography"
               categoryMessage="simpleMsghere"/>
             <ProblemCategory  categoryName="Cracking"
               categoryMessage="simpleMsghere"/>
         </div>


        </div>
    );
  }
}
