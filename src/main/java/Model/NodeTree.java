package Model;

import java.util.ArrayList;
import java.util.List;

public class NodeTree {
    String name;
    String owner;
    String sdt;
    String email;
    List<NodeTree> node_child;
    public NodeTree(){}
    public NodeTree(String name, List<NodeTree> list){
        this.name = name;
        this.node_child = list;
    }
    public NodeTree(String name, String owner, String sdt, String email, List<NodeTree> list){
        this.name = name;
        this.owner = owner;
        this.sdt = sdt;
        this.email = email;
        this.node_child = list;
    }
    public void Add_NodeChild(NodeTree node){
        this.node_child.add(node);
    }
    public String getName(){return this.name;}
    public void setName (String name) { this.name = name;}
    public String getOwner(){return this.owner;}
    public void setOwner (String owner) { this.owner = owner;}
    public String getSdt(){return this.sdt;}
    public void setSdt (String s) { this.sdt = sdt;}
    public String getEmail(){return this.email;}
    public void setEmail (String email) { this.email = email;}
    public List<NodeTree> getNode_child(){return this.node_child;}
    public void setNode_child (List<NodeTree> node_child) { this.node_child = node_child;}
}
