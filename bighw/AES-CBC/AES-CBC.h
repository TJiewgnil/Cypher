#include<sstream>
#include<string>
#include<vector>
#include<iostream>
#include <fstream>
#include <random>
using std::random_device;
using std::default_random_engine;
using namespace std;
#define encrypt 0
#define decrypt 1



string cbc(string& text, string& key, string& iv);

string in_cbc(string& text, string& key, string& pre);