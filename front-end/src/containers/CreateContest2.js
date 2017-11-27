import React, { Component } from 'react';
import ProblemCategory from '../components/ProblemCategory' ;
import axios from 'axios';
import { Button,Breadcrumb } from 'react-bootstrap';
import  DatePicker from 'react-bootstrap-date-picker' ;
import { Modal } from 'react-bootstrap';
export default class CreateContest2 extends Component {




constructor(props) {
        super(props);
        this.state = {
           show: false
        };
      }



componentWillMount()
{
        //********here we will GET DATA from redux to chekc if user authenticated o
        //********not
}



saveChallenge = () =>{

  console.log("clicke cliecked");
  this.setState({ show: false});
}



OpenModal()
{
  return(
    <div className="static-modal">
    <Modal.Dialog>
      <Modal.Header>
        <Modal.Title>Modal title</Modal.Title>
      </Modal.Header>

      <Modal.Body>
        One fine body...
      </Modal.Body>

      <Modal.Footer>
        <Button>Close</Button>
        <Button bsStyle="primary">Save changes</Button>
      </Modal.Footer>

    </Modal.Dialog>
  </div>
  )
}







  render() {
 let close = () => this.setState({ show: false});
    return (

<div className="container">


  <div class="row">

  <div class="alert alert-light" role="alert">

Contest Challenges
  </div>

  </div>

<hr/>


<br/>



  <div className="row">

    <button type="submit"
onClick={() => this.setState({ show: true})}

       className="btn btn-success">Add Challenge  </button>
  </div>


  <Modal
          show={this.state.show}
          onHide={close}
          container={this}
          aria-labelledby="contained-modal-title"
        >
          <Modal.Header closeButton>
            <Modal.Title id="contained-modal-title">Add Chaellenge</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <div className="form-group">
         <label for="email">Challenge Name:</label>
         <input type="email" className="form-control" id="email" />
             </div>

             <div className="form-group">
          <label for="email">Max Score</label>
          <input type="number" className="form-control" id="email" />
              </div>

          </Modal.Body>
          <Modal.Footer>
                <Button  onClick={() => this.saveChallenge()} bsStyle="primary">Add Challenge</Button>
            <Button onClick={close}>Close</Button>
          </Modal.Footer>
        </Modal>













        </div>
    );
  }
}
