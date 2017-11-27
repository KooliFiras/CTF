



let  getData = (dataURL, headers) => {
  let result = {
    data: [],
    message: ''
  };
  if (dataURL === null || dataURL === undefined || dataURL === '') {
    result.message = 'URL is not correct';
    responseData(result);
  }
  return fetch(dataURL, headers)
    .then(response =>{
      if (response.ok) {
        response.json().then(data => {
          result.data = data;
          result.message = response.statusText;
          responseData(result);
        });
      }else{
        result.message = 'Network response was not ok.';
        responseData(result);
      }
      return result;
    })
    .catch(err => console.log(err));
};





//***************functions ****************//
function CreateContest()
{



}


//***********function to submit a solution*************//
function ResolveProblem()
{


}


//*************function to participate in Contest
function particpateContest()
{

}


export default { particpateContest,ResolveProblem,CreateContest, getData }
