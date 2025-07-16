from fastapi import FastAPI, Depends, HTTPException, status 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel


class Data(BaseModel):
  name: str   # we are creatign thsi data for post function to see how t oaccept request from the user 


app =FastAPI()
# path parameter 
@app.get("/test/{item_id}/")
async def test(item_id: str, query:int=1):
  return{"Hello world": item_id} # by writing int = 1 we can make this query optional , means it is not necessary required 

# Lets see how to accept request 
@app.post("/create/")
async def create(data:Data):
  return {"data":data}