#ifndef STRUCTS_H
#define STRUCTS_H

#include <QString>

#define DELETE_RULE_COMMAND 0
#define ADD_RULE_COMMAND 1
#define UPDATE_RULE_COMMAND 2

struct Rule{
    unsigned int id_rule;
    unsigned int in_out;
    QString ip_src;
    QString ip_dest;
    int port_src;
    int port_dest;
    unsigned int proto;
    unsigned int action;
    QString host_name_dest;
    QString host_name_src;
};

struct RuleToKernel{
    unsigned int id_rule;
    unsigned int in_out;
    char * ip_src;
    char * ip_dest;
    int port_src;
    int port_dest;
    unsigned int proto;
    unsigned int action;
};

struct Command{
    int action;
    struct RuleToKernel * rule;
};

#endif // STRUCTS_H
