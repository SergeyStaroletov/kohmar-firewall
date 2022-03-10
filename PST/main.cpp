#include <string.h>
#include <stdio.h>
#include "pst_predictor.h"
#include "pst_samples.h"

using namespace std;

int main()
{
	PstPredictor * predictor = new PstPredictor();
	Samples * samples = new Samples();
	int maxlen;

	maxlen = samples->loadFromFile("http.samples");

	if(maxlen == -1)
		return 0;

	/*
	char * s1 = new char[20];
	char * s2 = new char[20];
	char * s3 = new char[20];
	strcpy(s1, "1326262662R2R2");
	strcpy(s2, "13232RR2");
	strcpy(s3, "1326262662662662RR2");

	samples->add(s1);
	samples->add(s2);
	samples->add(s3);
	*/

	//printf("%d", samples->numOfSamples());

	char * toPredict = new char[20];
	strcpy(toPredict, "13R");

	//char * seq = new char[20];
	//strcpy(seq, "bra");

	//predictor->init(256, 0.0001, 0, 0.0001, 1.05, 20);
	predictor->init(256, 0.0001, 2, 0.000001, 2, maxlen, 1);
	predictor->learn(samples);

	printf("\nLearned!");

	//predictor->root->printRecursively();

	double loge = predictor->logEval(toPredict);
	printf("\nlogEval = %f", loge);

	predictor->retrainForSeq(toPredict);
	loge = predictor->logEval(toPredict);
	printf("\nafter_retrain_logEval = %f", loge);

	//printf("\nP(%c|%s) = %f", ch, seq, predictor->predict(ch, seq));

	return 1;
}
