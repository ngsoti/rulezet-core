sudo apt install python3.12-venv
# install python requirements
python3 -m venv env
. env/bin/activate
pip install -r requirements.txt


./install_postgresql.sh



# make launch script executable
./launch.sh -i