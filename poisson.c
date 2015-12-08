#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <tgmath.h>
#include <string.h>
#define MAX_CACHE 1000000
long double cache_log[MAX_CACHE];
long double cache_sum[MAX_CACHE];

int init_cache()        {
        int i=1;

        for(; i<MAX_CACHE; i++)
                cache_log[i] = logl((long double)i);

        memset(cache_sum, 0x0, MAX_CACHE);

}
long double poisson(int k, int lam)     {

        int c = 1;
        long double pvalue = 0;
        long double sum = 0;

        if ( cache_sum[k] )
                sum = cache_sum[k];
        else {
                while(c <= k)   {
                        sum += cache_log[c];
                        c++;
                }
                cache_sum[k] = sum;
        }

        pvalue = cache_log[2] + k*cache_log[lam] - sum - lam;

        return pvalue;
}
int main(int argc, char **argv) {
        float threshold = 0.001;
        init_cache();
        int mean = atoi(argv[1]);
        int i = 0;

        for(i=mean;i<50000;i++) {
                //T é o retorno da poisson, i é o current packets e mean é a baseline
                float t = 1 - (1 + 1/poisson(i, mean));
                        if ( t < threshold)    {
                                printf("Mean : %d Th : %LF  Alert : %d\n", mean, 1 - (1 + 1/poisson(i, 100)), i);
                                exit(0);
                        }
        }
}