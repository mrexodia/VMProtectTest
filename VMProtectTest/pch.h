// 作業を開始するためのヒント: 
//    1. ソリューション エクスプローラー ウィンドウを使用してファイルを追加/管理します 
//   2. チーム エクスプローラー ウィンドウを使用してソース管理に接続します
//   3. 出力ウィンドウを使用して、ビルド出力とその他のメッセージを表示します
//   4. エラー一覧ウィンドウを使用してエラーを表示します
//   5. [プロジェクト] > [新しい項目の追加] と移動して新しいコード ファイルを作成するか、[プロジェクト] > [既存の項目の追加] と移動して既存のコード ファイルをプロジェクトに追加します
//   6. 後ほどこのプロジェクトを再び開く場合、[ファイル] > [開く] > [プロジェクト] と移動して .sln ファイルを選択します

#ifndef PCH_H
#define PCH_H

// https://github.com/intelxed/xed
extern "C"
{
#include <xed/xed-interface.h>
}

// TODO: ここでプリコンパイルするヘッダーを追加します
#include <Windows.h>

// C++
#include <array>
#include <list>
#include <map>
#include <memory>
#include <stack>
#include <set>
#include <vector>

#include <sstream>
#include <iostream>

// triton
#include <triton/api.hpp>
#include <triton/ast.hpp>
#include <triton/x86Specifications.hpp>

#endif //PCH_H
