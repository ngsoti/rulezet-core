# install python requirements
python3 -m venv env
. env/bin/activate
pip install -r requirements.txt
# init submodules
# git submodule init && git submodule update

./install_postgresql.sh



# make launch script executable
./launch.sh -i