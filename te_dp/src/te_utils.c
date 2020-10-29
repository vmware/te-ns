//**********************************************************************************************
// Traffic Emulator for Network Services
// Copyright 2020 VMware, Inc
// The BSD-2 license (the "License") set forth below applies to all parts of
// the Traffic Emulator for Network Services project. You may not use this file
// except in compliance with the License.
//
// BSD-2 License
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE
//**********************************************************************************************

#ifndef TE_UTILS_H
#include "te_utils.h"
#endif

/***************** Utilities for balanced BST (Error Metrics) *****************/
// Utility function to get the height of the tree
int height(te_error_metrics_t *N)
{
    if (N == NULL)
        return 0;
    return N->height;
}

// Utility function to get maximum of two integers
int max(int a, int b)
{
    return (a > b)? a : b;
}

/* Helper function that allocates a new node*/
te_error_metrics_t* new_error_node(int error_int, const char* error_name, te_http_url_metrics_t* url_metric)
{
    time_t curtime;
    te_error_metrics_t* node;
    te_malloc(node, sizeof(te_error_metrics_t), TE_MTYPE_ERROR_METRICS);
    node->error_int   = error_int;
    int len = strlen(error_name);
    te_malloc(node->error_name, len * sizeof(char) + 1, TE_MTYPE_CHAR);
    snprintf(node->error_name, len+1, "%s", error_name);
    node->err_counter = 1;
    node->start_time  = time(&curtime);
    node->end_time    = time(&curtime);
    node->left        = NULL;
    node->right       = NULL;
    node->height      = 1;

    url_metric->num_error_buckets += 1;
    return node;
}

/* Utility function to right rotate subtree rooted with y */
te_error_metrics_t *rightRotate(te_error_metrics_t *y)
{
    te_error_metrics_t *x = y->left;
    te_error_metrics_t *T2 = x->right;

    // Perform rotation
    x->right = y;
    y->left = T2;

    // Update heights
    y->height = max(height(y->left), height(y->right))+1;
    x->height = max(height(x->left), height(x->right))+1;

    // Return new root
    return x;
}

/* Utility function to left rotate subtree rooted with x */
te_error_metrics_t *leftRotate(te_error_metrics_t *x)
{
    te_error_metrics_t *y = x->right;
    te_error_metrics_t *T2 = y->left;

    // Perform rotation
    y->left = x;
    x->right = T2;

    //  Update heights
    x->height = max(height(x->left), height(x->right))+1;
    y->height = max(height(y->left), height(y->right))+1;

    // Return new root
    return y;
}

/* Get Balance factor of node N */
int getBalance(te_error_metrics_t *N)
{
    if (N == NULL)
        return 0;
    return height(N->left) - height(N->right);
}

/* To update if the nodes already exists */
void update(te_error_metrics_t* node) {
    time_t curtime;
    node->err_counter += 1;
    node->end_time    = time(&curtime);
}

/* Recursive function to insert in the subtree rooted */
te_error_metrics_t* insert_or_update_error(te_error_metrics_t* node, int error_int, \
    const char* error_name, te_http_url_metrics_t* url_metric)
{
    /* 1.  Perform the normal BST insertion */
    if (node == NULL) {
        return new_error_node(error_int, error_name, url_metric);
    }

    if (error_int < node->error_int)
        node->left  = insert_or_update_error(node->left, error_int, error_name, url_metric);
    else if (error_int > node->error_int)
        node->right = insert_or_update_error(node->right, error_int, error_name, url_metric);
    else // Equal keys ==> Update metrics
        update(node);

    /* 2. Update height of this ancestor node */
    node->height = 1 + max(height(node->left), height(node->right));

    /* 3. Get the balance factor of this ancestor
          node to check whether this node became
          unbalanced */
    int balance = getBalance(node);

    // If this node becomes unbalanced, then there are 4 cases

    // Left Left Case
    if (balance > 1 && error_int < node->left->error_int)
        return rightRotate(node);

    // Right Right Case
    if (balance < -1 && error_int > node->right->error_int)
        return leftRotate(node);

    // Left Right Case
    if (balance > 1 && error_int > node->left->error_int) {
        node->left =  leftRotate(node->left);
        return rightRotate(node);
    }

    // Right Left Case
    if (balance < -1 && error_int < node->right->error_int) {
        node->right = rightRotate(node->right);
        return leftRotate(node);
    }

    /* return the (unchanged) node pointer */
    return node;
}
/***************** End of Utilities for balanced BST (Error Metrics) *****************/


unsigned int te_random(unsigned int min, unsigned int max)
{
    if (min > max) {
        min = min ^ max;
        max = min ^ max;
        min = min ^ max;
    }
    else if ( min == max) {
        return max;
    }
    return (rand()%(max-min))+min;
}

inline void te_swap (short *a, short *b)
{
    short temp;
    assert(a != NULL);
    assert(b != NULL);
    if (a == b) {
        return;
    }
    temp = *a;
    *a = *b;
    *b = temp;
}
